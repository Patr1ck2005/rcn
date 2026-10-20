"""Generate the fixed reverse-SSH startup contract for Windows workers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
import hashlib
import json
import os
import re
import tempfile
from urllib.parse import urlparse
from xml.sax.saxutils import escape

from .models import MachineExecutionConfig
from .tunnel_guard import build_guard_script


@dataclass(frozen=True)
class TunnelScript:
    machine_id: str
    script: str
    task_name: str


@dataclass(frozen=True)
class TunnelTaskBundle:
    machine_id: str
    script: TunnelScript
    task_xml: str
    task_name: str


@dataclass(frozen=True)
class CoordinatedTunnelBundle:
    """Nonsealed OS tasks; the supervisor's configured name is request-only."""
    machine_id: str
    root_uuid: str
    script_path: str
    script: str
    guard_task_name: str
    request_task_name: str
    guard_task_xml: str
    request_task_xml: str
    coordinator_host: str
    coordinator_port: int
    coordinator_user: str
    reverse_forward_host: str
    reverse_forward_port: int
    identity_file: str
    known_hosts_file: str
    member_sid: str | None = None
    member_owner_sid: str | None = None
    member_control_file: str | None = None


def build_coordinated_tunnel_bundle(
    config: MachineExecutionConfig, *, identity_file: str, known_hosts_file: str,
    allow_sshd_restart: bool = False,
) -> CoordinatedTunnelBundle:
    """Generate an opt-in pair. Never install tasks or change a live config.

    A rollout must verify both exact task definitions before pointing the sealed
    supervisor at the request task. Existing legacy installations are not silently
    replaced. Separate HTTPS heartbeat provisioning is a prerequisite, not proven
    merely by the presence of these configuration references.
    """
    if config.tunnel_startup != 'boot' or not config.root_uuid:
        raise ValueError('coordinated recovery requires boot startup and an accepted root identity')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,160}', config.tunnel_task_name):
        raise ValueError('unsafe task name')
    url = urlparse(config.control_plane_heartbeat_url or '')
    if (url.scheme != 'https' or not url.hostname or url.username or url.password or url.fragment
            or url.query or url.hostname in {'localhost', '127.0.0.1', '::1'}):
        raise ValueError('coordinated recovery requires a separately provisioned HTTPS heartbeat')
    from .remote_storage import validate_remote_root_path

    root = validate_remote_root_path(config.remote_root.replace('/', '\\'))
    for path in (identity_file, known_hosts_file, config.machine_token_file):
        if not path:
            raise ValueError('protected identity, host pin and machine-token references are required')
        candidate = PureWindowsPath(path)
        if not candidate.is_absolute() or '..' in candidate.parts or not candidate.is_relative_to(root) or candidate == root:
            raise ValueError('coordinated credentials must stay inside the managed root')
    errors = validate_startup_configuration(config)
    if errors:
        raise ValueError('; '.join(errors))
    guard_name = config.tunnel_task_name + '-Guard'
    script_path = str(root / 'agent' / 'tunnel' / 'managed-reverse-ssh.ps1')
    script = build_guard_script(config, identity_file=identity_file, known_hosts_file=known_hosts_file,
        allow_sshd_restart=allow_sshd_restart, guard_task_name=guard_name, require_remote_observation=True)
    executable = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    def xml(action: str, name: str, *, boot: bool) -> str:
        arguments = f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{script_path}" -Action {action}'
        triggers = '<BootTrigger><Enabled>true</Enabled></BootTrigger>' if boot else ''
        retry = '<RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>' if boot else ''
        return rf'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>RCN coordinated transport: {escape(name)}</Description></RegistrationInfo>
  <Triggers>{triggers}</Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><StartWhenAvailable>true</StartWhenAvailable><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>{retry}<ExecutionTimeLimit>{'PT0S' if boot else 'PT30S'}</ExecutionTimeLimit></Settings>
  <Actions Context="Author"><Exec><Command>{escape(executable)}</Command><Arguments>{escape(arguments)}</Arguments><WorkingDirectory>C:\Windows\System32</WorkingDirectory></Exec></Actions>
</Task>
'''
    return CoordinatedTunnelBundle(machine_id=config.machine_id, root_uuid=config.root_uuid,
        script_path=script_path, script=script, guard_task_name=guard_name,
        request_task_name=config.tunnel_task_name, guard_task_xml=xml('Run', guard_name, boot=True),
        request_task_xml=xml('RequestRecovery', config.tunnel_task_name, boot=False),
        coordinator_host=config.coordinator_host, coordinator_port=config.coordinator_port,
        coordinator_user=config.coordinator_user, reverse_forward_host=config.reverse_forward_host,
        reverse_forward_port=config.reverse_forward_port, identity_file=str(identity_file),
        known_hosts_file=str(known_hosts_file))


def coordinated_bundle_files(bundle: CoordinatedTunnelBundle, *, include_activation: bool = False) -> dict[str, bytes]:
    """Deterministic non-secret files, also consumed by the resumable installer."""
    contents = {'managed-reverse-ssh.ps1': bundle.script.encode('utf-8-sig'),
                'guard-task.xml': bundle.guard_task_xml.encode('utf-16'),
                'recovery-request-task.xml': bundle.request_task_xml.encode('utf-16')}
    from .tunnel_installation import build_task_installer

    payload_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
    contents['install-coordinated-tunnel.ps1'] = build_task_installer(bundle, payload_hashes, include_activation=include_activation).encode('utf-8-sig')
    manifest = {'schema_version': 1, 'kind': 'coordinated-member-tunnel', 'installed': False,
        'machine_id': bundle.machine_id, 'root_uuid': bundle.root_uuid,
        'script_path': bundle.script_path, 'guard_task_name': bundle.guard_task_name,
        'supervisor_tunnel_task_name': bundle.request_task_name,
        'installer_mode': ('preview-stage-disabled-activate-status-rollback' if include_activation else 'preview-stage-disabled-verify-rollback'),
        'files_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
        'rollout_gates': ['paused-idle', 'protected-root-and-keys', 'independent-heartbeat-verified',
                         'review-exact-existing-tasks', 'register-both-tasks', 'end-run-coordination-acceptance',
                         'retire-only-verified-legacy-objects']}
    contents['manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode('utf-8')
    return contents


def write_coordinated_tunnel_bundle(bundle: CoordinatedTunnelBundle, output: Path, *, include_activation: bool = False) -> dict:
    """Export reviewable non-secret task files; never overwrite a prior bundle."""
    output = Path(output).absolute()
    for parent in (output, *output.parents):
        if parent.is_symlink() or (parent.exists() and getattr(parent.lstat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError('linked bundle output is forbidden')
    if output.exists():
        raise FileExistsError('bundle output already exists')
    output.parent.mkdir(parents=True, exist_ok=True)
    contents = coordinated_bundle_files(bundle, include_activation=include_activation)
    manifest = json.loads(contents.pop('manifest.json'))
    with tempfile.TemporaryDirectory(prefix='rcn-tunnel-bundle-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'bundle'
        stage.mkdir()
        for name, data in contents.items():
            (stage / name).write_bytes(data)
        (stage / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        # Exclusive directory claim works on both Windows and POSIX, including
        # an empty directory concurrently created by another publisher. Publish
        # the manifest LAST: a partial export can never look like a full bundle.
        output.mkdir()
        for name in contents:
            os.link(stage / name, output / name)
        os.link(stage / 'manifest.json', output / 'manifest.json')
    return {**manifest, 'manifest_sha256': hashlib.sha256((output / 'manifest.json').read_bytes()).hexdigest()}


def _ps_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def build_reconnect_script(
    config: MachineExecutionConfig,
    *,
    identity_file: str | None = None,
    known_hosts_file: str | None = None,
    allow_sshd_restart: bool = False,
) -> TunnelScript:
    """Return a script with no embedded secret or private-key contents."""
    if config.tunnel_startup == "manual":
        raise ValueError("tunnel startup is manual; select logon or boot before generating a task")
    if not config.machine_id or not config.tunnel_task_name:
        raise ValueError("machine and task names are required")
    if config.control_plane_heartbeat_url or config.machine_token_file:
        raise ValueError(
            "independent heartbeat requires a coordinated guard/request task bundle; "
            "the single-task layout can cause supervisor restart churn"
        )
    errors = validate_startup_configuration(config)
    if errors:
        raise ValueError("; ".join(errors))
    return TunnelScript(config.machine_id, build_guard_script(
        config, identity_file=identity_file, known_hosts_file=known_hosts_file,
        allow_sshd_restart=allow_sshd_restart,
    ), config.tunnel_task_name)


def build_task_scheduler_command(script_path: str | Path, config: MachineExecutionConfig) -> list[str]:
    if config.tunnel_startup not in {"logon", "boot"}:
        raise ValueError("task scheduler requires logon or boot startup")
    return ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script_path)]


def build_tunnel_task_bundle(
    config: MachineExecutionConfig,
    script_path: str | Path,
    *,
    identity_file: str | None = None,
    known_hosts_file: str | None = None,
    run_as: str = "SYSTEM",
    allow_sshd_restart: bool = False,
) -> TunnelTaskBundle:
    """Build the script and scheduler XML as one auditable deployment unit."""
    script = build_reconnect_script(
        config,
        identity_file=identity_file,
        known_hosts_file=known_hosts_file,
        allow_sshd_restart=allow_sshd_restart,
    )
    return TunnelTaskBundle(
        machine_id=config.machine_id,
        script=script,
        task_xml=build_boot_task_xml(config, script_path, run_as=run_as),
        task_name=config.tunnel_task_name,
    )


def build_boot_task_xml(
    config: MachineExecutionConfig,
    script_path: str | Path,
    *,
    run_as: str = "SYSTEM",
) -> str:
    """Create a password-free Windows boot task.

    ``S4U`` is not valid for many local Windows accounts (and fails with the
    misleading ``security identifier could not be mapped`` error).  The
    default therefore uses the built-in SYSTEM service account.  The caller
    must place the OS-managed identity and pinned known-hosts file in a path
    readable by SYSTEM and ACL it explicitly; no key bytes are ever embedded
    in this XML.  ``run_as='user'`` remains available for installations that
    have a domain account with a supported S4U logon.
    """
    if config.tunnel_startup != "boot":
        raise ValueError("boot task XML requires tunnel_startup=boot")
    command = " ".join(f'\"{part}\"' if " " in part else part for part in build_task_scheduler_command(script_path, config))
    if run_as == "SYSTEM":
        user_id = "S-1-5-18"
        # Task Scheduler infers the service account from the SID.  Including
        # ``ServiceAccount`` is rejected by older Windows 10 task engines.
        logon_type = ""
        run_level = "HighestAvailable"
    elif run_as == "user":
        user_id = f".\\{config.ssh_user}"
        logon_type = "S4U"
        run_level = "LeastPrivilege"
    else:
        raise ValueError("run_as must be SYSTEM or user")
    return f"""<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">
  <RegistrationInfo><Description>{escape(config.tunnel_task_name)} reverse SSH tunnel</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id=\"Author\"><UserId>{escape(user_id)}</UserId>{f'<LogonType>{logon_type}</LogonType>' if logon_type else ''}<RunLevel>{run_level}</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><StartWhenAvailable>true</StartWhenAvailable><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
  <Actions Context=\"Author\"><Exec><Command>{escape(command.split(' ', 1)[0])}</Command><Arguments>{escape(command.split(' ', 1)[1])}</Arguments><WorkingDirectory>C:\\Windows\\System32</WorkingDirectory></Exec></Actions>
</Task>
"""


def validate_startup_configuration(config: MachineExecutionConfig) -> list[str]:
    errors: list[str] = []
    if config.tunnel_startup == "boot" and not config.coordinator_host:
        errors.append("coordinator_host is required for boot startup")
    if config.reverse_forward_port < 1024:
        errors.append("reverse_forward_port must be an unprivileged port")
    if not config.coordinator_user or any(ch in config.coordinator_user for ch in "\\/:*?\"<>|@"):
        errors.append("coordinator_user is invalid")
    if "PRIVATE KEY" in config.pinned_host_key.upper():
        errors.append("private key material cannot be stored in execution config")
    return errors
