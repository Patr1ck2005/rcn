"""One member setup call drives reviewed Stage -> Activate without manual hashes.

No elevation, credential exchange, arbitrary command, service restart, or compute
admission is hidden here. The caller has just rechecked the signed relay/root
context. Existing activation is observed/resumed; never roll back a live task.
"""
from __future__ import annotations

import hashlib
from pathlib import Path, PureWindowsPath
import re
import subprocess

from . import member_registration as storage

FILES = {'managed-reverse-ssh.ps1', 'guard-task.xml', 'recovery-request-task.xml', 'install-coordinated-tunnel.ps1'}
MODE = 'preview-stage-disabled-activate-status-rollback'


def _fail(code):
    raise storage.MemberRegistrationError(code)


def _activation_receipt_shape(value):
    """Validate legacy and current native receipt keys without granting authority.

    Current reviewed native scripts report the number of retired legacy tunnel
    processes. This is a bounded informational count, not permission to retire
    anything, proof of transport health, or permission to execute science.
    """
    fields = {'state','machine_id','root_uuid','task_name','task_enabled','launch_requested',
              'instance_guid','transport_verified','heartbeat_verified','grants_execution','stop_marker'}
    if not isinstance(value, dict) or set(value) not in (fields, fields | {'legacy_retired_count'}):
        return False
    return ('legacy_retired_count' not in value
            or (type(value['legacy_retired_count']) is int
                and 0 <= value['legacy_retired_count'] <= 2147483647))


def install_member_tunnel(*, worker_root: Path, machine_id: str, root_uuid: str,
                          expected_manifest_sha256: str, accept_activation: bool = False,
                          execution_identity=None, state_root=None) -> dict:
    """Register/enable the bounded transport pair, with honest task-only status."""
    if accept_activation is not True:
        _fail('explicit_tunnel_activation_consent_required')
    if not re.fullmatch(r'[a-f0-9]{64}', expected_manifest_sha256):
        _fail('invalid_tunnel_activation_digest')
    root = Path(worker_root).absolute()
    directory = root / 'agent/tunnel/relay-bundle'
    try:
        storage._private_directory(directory, create=False)
        with storage._exclusive(directory):
            manifest_path = directory / 'manifest.json'
            storage._check_private_file(manifest_path)
            manifest_raw = storage._read_bytes(manifest_path, maximum=65536)
            manifest = storage._json_document(manifest_raw)
            expected_path = PureWindowsPath(root) / 'agent/tunnel/managed-reverse-ssh.ps1'
            if (hashlib.sha256(manifest_raw).hexdigest() != expected_manifest_sha256
                    or manifest.get('schema_version') != 1 or type(manifest.get('schema_version')) is not int
                    or manifest.get('kind') != 'coordinated-member-tunnel'
                    or manifest.get('machine_id') != machine_id or manifest.get('root_uuid') != root_uuid
                    or manifest.get('installer_mode') != MODE
                    or PureWindowsPath(manifest.get('script_path', '')) != expected_path
                    or manifest.get('guard_task_name') != 'RCN-Member-' + root_uuid + '-Guard'
                    or manifest.get('supervisor_tunnel_task_name') != 'RCN-Member-' + root_uuid
                    or set(manifest.get('files_sha256', {})) != FILES):
                _fail('member_tunnel_bundle_requires_reviewed_upgrade')
            snapshots = {'manifest.json': manifest_raw}
            for name in sorted(FILES):
                storage._check_private_file(directory / name)
                raw = storage._read_bytes(directory / name, maximum=262144)
                if hashlib.sha256(raw).hexdigest() != manifest['files_sha256'][name]:
                    _fail('member_tunnel_bundle_changed')
                snapshots[name] = raw

            def unchanged():
                for name, raw in snapshots.items():
                    storage._check_private_file(directory / name)
                    if storage._read_bytes(directory / name, maximum=262144) != raw:
                        _fail('member_tunnel_bundle_changed')

            def call(action, confirmation=None):
                unchanged()
                if execution_identity is not None:
                    from .member_execution_identity import run_tunnel_action
                    value = run_tunnel_action(execution_identity, directory/'install-coordinated-tunnel.ps1',
                        installer_sha256=manifest['files_sha256']['install-coordinated-tunnel.ps1'],
                        manifest_sha256=expected_manifest_sha256, action=action, confirmation=confirmation,
                        state_root=state_root or root.parent/'owner-control/tunnel-helper')
                    unchanged()
                    return value
                args = ['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
                        str(directory / 'install-coordinated-tunnel.ps1'), '-Action', action,
                        '-ExpectedManifestSha256', expected_manifest_sha256]
                if confirmation is not None:
                    args += ['-ConfirmationHash', confirmation]
                result = subprocess.run(args, capture_output=True, timeout=45, check=False)
                unchanged()
                if result.returncode or len(result.stdout) > 16384:
                    _fail('member_tunnel_install_unconfirmed_preserve_state')
                value = storage._json_document(result.stdout)
                if not isinstance(value, dict):
                    _fail('member_tunnel_install_receipt_invalid')
                return value

            def confirmation(value, state):
                tasks = [manifest['guard_task_name'], manifest['supervisor_tunnel_task_name']]
                if value.get('task_names') != tasks:
                    _fail('member_tunnel_install_receipt_invalid')
                if state == 'activation-preview':
                    if (value.get('root_uuid') != root_uuid or value.get('grants_execution') is not False
                            or value.get('transport_verified') is not False):
                        _fail('member_tunnel_install_receipt_invalid')
                elif value.get('installs_disabled') is not True or value.get('activates') is not False:
                    _fail('member_tunnel_install_receipt_invalid')
                if (value.get('state') != state or value.get('machine_id') != machine_id
                        or not isinstance(value.get('confirmation_hash'), str)
                        or not re.fullmatch(r'[a-f0-9]{64}', value['confirmation_hash'])):
                    _fail('member_tunnel_install_receipt_invalid')
                return value['confirmation_hash']

            activation_path = root / 'agent/tunnel/coordinated-activation.json'
            storage._check_private_file(activation_path)
            if not activation_path.exists():
                stage_path = root / 'agent/tunnel/coordinated-install.json'
                storage._check_private_file(stage_path)
                if stage_path.exists():
                    checked = call('Verify')
                    if checked.get('state') != 'staged' or checked.get('activates') is not False:
                        _fail('member_tunnel_install_requires_original_recovery')
                else:
                    choice = confirmation(call('Preview'), 'preview')
                    staged = call('Stage', choice)
                    if staged.get('state') != 'staged' or staged.get('activates') is not False:
                        _fail('member_tunnel_install_receipt_invalid')
            # The native action reads the canonical journal and performs all OS
            # comparisons again. A client-side file is never a success receipt.
            status = call('ActivationStatus')
            if status.get('state') == 'not-requested':
                if (set(status) != {'state','grants_execution','transport_verified'}
                        or status['grants_execution'] is not False or status['transport_verified'] is not False):
                    _fail('member_tunnel_install_receipt_invalid')
            elif (status.get('grants_execution') is not False or status.get('transport_verified') is not False
                    or status.get('heartbeat_verified') is not False or status.get('machine_id') != machine_id
                    or status.get('root_uuid') != root_uuid or type(status.get('launch_requested')) is not bool):
                _fail('member_tunnel_install_receipt_invalid')
            if status.get('state') == 'not-requested' or status.get('launch_requested') is False:
                choice = confirmation(call('PreviewActivation'), 'activation-preview')
                status = call('Activate', choice)
            if (not _activation_receipt_shape(status) or status['machine_id'] != machine_id or status['root_uuid'] != root_uuid
                    or status['task_name'] != manifest['guard_task_name']
                    or status['state'] not in {'task-running','awaiting-task-observation','disabled-by-operator','blocked-by-marker'}
                    or any(type(status[k]) is not bool for k in ('task_enabled','launch_requested'))
                    or any(status[k] is not False for k in ('transport_verified','heartbeat_verified','grants_execution'))):
                _fail('member_tunnel_install_receipt_invalid')
            return {'tunnel_tasks_installed': True, 'tunnel_tasks_enabled': status['task_enabled'],
                    'tunnel_task_running': status['state'] == 'task-running',
                    'tunnel_activation': status, 'ssh_verified': False, 'heartbeat_verified': False,
                    'grants_execution': False}
    except storage.MemberRegistrationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
        _fail('member_tunnel_install_unconfirmed_preserve_state')
