"""Current-user zero-capacity supervisor task; never elevates or stops work.

The original sealed supervisor is executed directly with -B. A minute watchdog
and its existing single-instance lock cover loss between intent and task.Run.
Native Scheduler operations are isolated in one testable boundary. No passwords,
SYSTEM execution, host reboot, arbitrary commands or compute approval are used.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from xml.sax.saxutils import escape

import psutil

from . import member_registration as storage
from .member_runtime import CONFIG, JOURNAL, _fail
from .runtime_policy import STABLE_RUNTIME_VERSION

STARTUP_JOURNAL = 'member-supervisor-startup.json'


def _native(script: str) -> dict:
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand',
        base64.b64encode(script.encode('utf-16-le')).decode('ascii')], capture_output=True, timeout=30)
    if result.returncode or len(result.stdout) > 16384:
        _fail('member_supervisor_task_unconfirmed')
    return storage._json_document(result.stdout)


def _sid() -> str:
    value = _native("$i=[Security.Principal.WindowsIdentity]::GetCurrent();@{sid=$i.User.Value}|ConvertTo-Json -Compress")
    sid = value.get('sid', '')
    if not isinstance(sid, str) or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', sid):
        _fail('member_supervisor_requires_interactive_member')
    return sid


def _xml(root: Path, python: Path, sid: str, start: str, version: str = STABLE_RUNTIME_VERSION) -> str:
    script = root/'agent/versions'/version/'remote-agent/supervisor.py'
    command = f'-B "{script}" --config "{root/CONFIG}" run'
    return f'''<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Description>RCN member supervisor; never a compute authorization</Description></RegistrationInfo>
<Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{escape(sid)}</UserId></LogonTrigger>
<TimeTrigger><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>{escape(start)}</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
<Principals><Principal id="Member"><UserId>{escape(sid)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure><Enabled>true</Enabled></Settings>
<Actions Context="Member"><Exec><Command>{escape(str(python))}</Command><Arguments>{escape(command)}</Arguments><WorkingDirectory>{escape(str(root))}</WorkingDirectory></Exec></Actions></Task>'''


TASK_SCRIPT = r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $spec.sid){throw 'Member identity changed'}
$service=New-Object -ComObject Schedule.Service;$service.Connect();$folder=$service.GetFolder('\')
$definition=$service.NewTask(0);$definition.XmlText=$spec.xml
function Canonical([string]$value){
 $x=[xml]::new();$x.XmlResolver=$null;$x.LoadXml($value)
 foreach($name in @('URI','Author','Date')){
  foreach($n in @($x.SelectNodes("/*[local-name()='Task']/*[local-name()='RegistrationInfo']/*[local-name()='$name']"))){$null=$n.ParentNode.RemoveChild($n)}
 }
 return $x.OuterXml
}
function Read-OwnTask {
 try{return $folder.GetTask($spec.task_name)}catch{
  $e=$_.Exception;while($e){if($e.HResult -eq -2147024894){return $null};$e=$e.InnerException};throw
 }
}
$task=Read-OwnTask
if($null -eq $task -and $spec.action -eq 'install'){
 # CREATE only, IGNORE registration triggers; no replacement or stored password.
 $sddl='O:'+$spec.sid+'G:'+$spec.sid+'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;'+$spec.sid+')'
 $null=$folder.RegisterTaskDefinition($spec.task_name,$definition,34,$spec.sid,$null,3,$sddl)
 $task=Read-OwnTask
}
if($null -eq $task){@{exists=$false;task_enabled=$false;task_running=$false}|ConvertTo-Json -Compress;exit 0}
$expected=$service.NewTask(0);$expected.XmlText=$definition.XmlText;$expected.Settings.Enabled=[bool]$task.Enabled
if((Canonical $task.Xml) -cne (Canonical $expected.XmlText)){throw 'Existing supervisor task differs'}
$security=[Security.AccessControl.RawSecurityDescriptor]::new([string]$task.GetSecurityDescriptor(7))
$allowed=@($spec.sid,'S-1-5-18','S-1-5-32-544')
if($security.Owner.Value -notin $allowed -or $null -eq $security.DiscretionaryAcl){throw 'Unprotected supervisor task'}
foreach($ace in $security.DiscretionaryAcl){
 if($ace.AceType.ToString() -notin @('AccessAllowed','AccessDenied')){throw 'Unknown supervisor ACL'}
 if($ace.AceType.ToString() -eq 'AccessAllowed' -and $ace.SecurityIdentifier.Value -notin $allowed){throw 'Foreign supervisor task access'}
}
if($spec.action -eq 'run' -and $task.Enabled){$null=$task.Run($null)}
$task=Read-OwnTask;$instances=@($task.GetInstances(0))
if($instances.Count -gt 1){throw 'Multiple supervisor task instances'}
@{exists=$true;task_enabled=[bool]$task.Enabled;task_running=([int]$task.State -eq 4)}|ConvertTo-Json -Compress
'''


def _task(action: str, spec: dict) -> dict:
    if action not in {'inspect', 'install', 'run'}:
        _fail('member_supervisor_invalid_action')
    literal = json.dumps({**spec, 'action': action}, ensure_ascii=True).replace("'", "''")
    value = _native("$spec='" + literal + "'|ConvertFrom-Json\n" + TASK_SCRIPT)
    if (not isinstance(value, dict) or set(value) != {'exists','task_enabled','task_running'}
            or any(type(v) is not bool for v in value.values())):
        _fail('member_supervisor_task_receipt_invalid')
    return value


def _status(root: Path, config: dict, python: Path) -> dict | None:
    path = root/'agent/status.json'
    if not path.is_file():
        return None
    storage._unlinked(path)
    try:
        value = storage._json_document(storage._read_bytes(path, maximum=65536))
        at = datetime.fromisoformat(value['updated_at'])
        if (at.tzinfo is None or not 0 <= (datetime.now(timezone.utc)-at).total_seconds() <= 15
                or any(value.get(k) != config[k] for k in ('machine_id','root_uuid','runtime_version'))
                or type(value.get('max_concurrent_units')) is not int or value['max_concurrent_units'] != 0
                or value.get('active_run_ids') != [] or type(value.get('pid')) is not int):
            return None
        p = psutil.Process(value['pid'])
        expected = [str(python), '-B', str(root/'agent/versions'/config['runtime_version']/'remote-agent/supervisor.py'),
                    '--config', str(root/CONFIG), 'run']
        actual = p.cmdline()
        if (len(actual) != len(expected) or any(a.casefold() != b.casefold() for a,b in zip(actual,expected))
                or Path(p.exe()) != python or p.create_time() > at.timestamp()):
            return None
        return {'pid':value['pid'], 'observed_at':value['updated_at'], 'capacity':0}
    except (OSError, ValueError, TypeError, KeyError, psutil.Error):
        return None


def start_member_supervisor(runtime: dict, *, accept_startup: bool = False) -> dict:
    if accept_startup is not True or runtime.get('worker_runtime_installed') is not True:
        _fail('member_supervisor_startup_consent_required')
    root = Path(runtime['worker_root']).absolute()
    if runtime.get('execution_identity') is not None:
        return _start_execution_supervisor(runtime, root)
    try:
        storage._private_directory(root/'agent', create=False)
        with storage._exclusive(root/'agent'):
            config_path = root/CONFIG
            storage._check_private_file(config_path)
            config_raw = storage._read_bytes(config_path)
            config = storage._json_document(config_raw)
            python = Path(runtime['python_executable']).with_name('pythonw.exe')
            storage._unlinked(python)
            if not python.is_file() or Path(runtime['supervisor_config_path']) != config_path:
                _fail('member_supervisor_runtime_identity_changed')
            if (config.get('runtime_version') != STABLE_RUNTIME_VERSION or config.get('remote_root') != str(root)
                    or config.get('python_executable') != runtime['python_executable']):
                _fail('member_supervisor_runtime_identity_changed')
            # Do not restore bootstrap capacity or undo a later acceptance/operator action.
            if config.get('enabled') is not False or config.get('target_concurrent_units') != 0:
                return {'supervisor_started': False, 'supervisor_startup_state':'configuration-advanced', 'grants_execution':False}
            if (type(config.get('target_concurrent_units')) is not int
                    or type(config.get('max_concurrent_units')) is not int or config['max_concurrent_units'] != 1):
                _fail('member_supervisor_requires_zero_capacity')
            marker = storage._json_document(storage._read_bytes(root/'.rcn-root.json'))
            if any(marker.get(k) != config.get(k) for k in ('machine_id','root_uuid')):
                _fail('member_supervisor_root_identity_changed')
            sid = _sid()
            name = 'RCN-Member-' + config['root_uuid'] + '-Supervisor'
            if not re.fullmatch(r'RCN-Member-[a-f0-9-]{36}-Supervisor', name):
                _fail('member_supervisor_invalid_task_identity')
            journal = root/'agent'/STARTUP_JOURNAL
            storage._check_private_file(journal)
            old = storage._read_bytes(journal) if journal.exists() else None
            state = storage._json_document(old) if old is not None else None
            if state is None:
                start = (datetime.now(timezone.utc)+timedelta(seconds=60)).isoformat()
                spec = {'sid':sid, 'task_name':name, 'xml':_xml(root,python,sid,start)}
                if _task('inspect',spec)['exists']:
                    _fail('member_supervisor_unowned_task')
                state = {'schema_version':1,'start_boundary':start,'sid':sid,'config_sha256':hashlib.sha256(config_raw).hexdigest(),
                         'phase':'installing','spec':spec}
                old = storage._json_bytes(state);storage._publish(journal,old)
            spec = {'sid':sid,'task_name':name,'xml':_xml(root,python,sid,state['start_boundary'])}
            if (set(state) != {'schema_version','start_boundary','sid','config_sha256','phase','spec'}
                    or type(state['schema_version']) is not int or state['schema_version'] != 1
                    or state['spec'] != spec or state['sid'] != sid
                    or state['config_sha256'] != hashlib.sha256(config_raw).hexdigest()
                    or state['phase'] not in {'installing','launch-requested'}):
                _fail('member_supervisor_startup_journal_changed')
            if state['phase'] == 'installing':
                observed = _task('install',spec)
                if not observed['exists']:
                    _fail('member_supervisor_registration_unconfirmed')
                if not observed['task_enabled']:
                    return {'supervisor_started':False,'supervisor_startup_state':'disabled-by-operator','grants_execution':False}
                state['phase']='launch-requested';storage._publish(journal,storage._json_bytes(state),expected=old)
                if storage._read_bytes(config_path) != config_raw:
                    _fail('member_supervisor_config_changed_before_launch')
                _task('run',spec)
            observed = _task('inspect',spec)
            if not observed['exists'] or not observed['task_enabled']:
                return {'supervisor_started':False,'supervisor_startup_state':'disabled-or-removed','grants_execution':False}
            # An uncertain Run is NOT reissued. The verified 1-minute trigger owns recovery.
            deadline = time.monotonic()+15
            evidence = _status(root,config,python)
            while evidence is None and time.monotonic()<deadline:
                time.sleep(.2);evidence = _status(root,config,python)
            return {'supervisor_started':evidence is not None,
                    'supervisor_startup_state':'running-zero-capacity' if evidence else 'awaiting-supervisor-heartbeat',
                    'supervisor_startup':'logon','supervisor_watchdog_seconds':60,
                    'supervisor_evidence':evidence,'heartbeat_verified':False,'grants_execution':False}
    except storage.MemberRegistrationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
        _fail('member_supervisor_startup_unconfirmed_preserve_state')


def _start_execution_supervisor(runtime, root):
    """Dedicated Password-logon account, triggered by the original owner's login."""
    from .member_execution_identity import observe_identity, register_execution_task
    from .member_release_catalog import release_for_runtime
    identity = runtime['execution_identity']
    if observe_identity(identity['root_uuid'], owner_sid=_sid()) != identity:
        _fail('member_supervisor_execution_identity_changed')
    config = storage._json_document(storage._read_bytes(root/CONFIG))
    release = release_for_runtime(config['runtime_version'])
    if (not release.owner_session_required or config['runtime_version'] != runtime['runtime_version']
            or config['remote_root'] != str(root) or config['root_uuid'] != identity['root_uuid']
            or runtime['python_executable'] != config['python_executable']):
        _fail('member_supervisor_runtime_identity_changed')
    python = Path(runtime['python_executable']).with_name('pythonw.exe')
    journal = root/'agent'/STARTUP_JOURNAL
    with storage._exclusive(root/'agent'):
        old = storage._read_bytes(journal) if journal.exists() else None
        state = storage._json_document(old) if old else None
        if state is None:
            state = {'schema_version': 2, 'root_uuid': identity['root_uuid'],
                'owner_sid': identity['owner_sid'], 'execution_sid': identity['execution_sid'],
                'runtime_version': release.runtime_version,
                'start_boundary': (datetime.now(timezone.utc)+timedelta(seconds=60)).isoformat()}
            storage._publish(journal, storage._json_bytes(state))
        if any(state.get(key) != value for key, value in {
                'schema_version': 2, 'root_uuid': identity['root_uuid'], 'owner_sid': identity['owner_sid'],
                'execution_sid': identity['execution_sid'], 'runtime_version': release.runtime_version}.items()):
            _fail('member_supervisor_startup_journal_changed')
        xml = _xml(root, python, identity['owner_sid'], state['start_boundary'], release.runtime_version)
        result = register_execution_task(identity, 'RCN-Member-'+identity['root_uuid']+'-Supervisor', xml,
            state_root=root.parent/'owner-control/supervisor-helper', start=True)
        evidence = _status(root, config, python)
        deadline = time.monotonic()+15
        while evidence is None and time.monotonic()<deadline:
            time.sleep(.2)
            evidence = _status(root, config, python)
        return {**result, 'supervisor_started': evidence is not None,
            'supervisor_startup_state': 'running-zero-capacity' if evidence else 'awaiting-supervisor-heartbeat',
            'supervisor_startup': 'logon', 'supervisor_watchdog_seconds': 60,
            'supervisor_evidence': evidence, 'heartbeat_verified': False, 'grants_execution': False}
