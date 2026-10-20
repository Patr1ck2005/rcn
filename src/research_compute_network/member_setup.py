"""Universal installer handoff: explicit consent and a pinned invitation snapshot.

Legacy enrollment remains separate. V2 normally prepares only member files.
Explicit transport activation uses its own guarded OS-task path, never the old
gateway/startup/welcome/browser path. No control-plane database is opened.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

from . import member_registration as registration

INSTALLER_HANDOFF_VERSION = 1


def setup_member(
    invitation_path: Path, *, expected_schema: int, invitation_sha256: str,
    accept_registration: bool = False, install_launcher: bool = True,
    install_startup: bool = False, open_browser: bool = False,
    prepare_worker: bool = False, worker_root: Path | None = None,
    prepare_relay: bool = False, configure_compute: bool = False, activate_tunnel: bool = False,
    runtime_archive: Path | None = None, start_supervisor: bool = False, connect_worker: bool = False,
    prepare_openssh: bool = False,
) -> dict:
    if accept_registration is not True:
        raise registration.MemberRegistrationError('registration_consent_required')
    if (type(start_supervisor) is not bool or (start_supervisor and runtime_archive is None)
            or (runtime_archive is not None and (not prepare_worker or expected_schema != 2))):
        raise registration.MemberRegistrationError('runtime_requires_explicit_worker_setup')
    if (type(connect_worker) is not bool or (connect_worker and (expected_schema != 2 or not prepare_worker
            or not prepare_relay or not start_supervisor or runtime_archive is None or not configure_compute))):
        raise registration.MemberRegistrationError('connect_worker_requires_complete_explicit_setup')
    if type(prepare_openssh) is not bool or (prepare_openssh and not connect_worker):
        raise registration.MemberRegistrationError('openssh_supply_requires_explicit_connection')
    if type(activate_tunnel) is not bool or (activate_tunnel and (not prepare_relay or not prepare_worker or expected_schema != 2)):
        raise registration.MemberRegistrationError('tunnel_activation_requires_explicit_worker_relay_setup')
    if type(configure_compute) is not bool or (configure_compute and not prepare_worker):
        raise registration.MemberRegistrationError('compute_configuration_requires_worker_preparation')
    if type(prepare_relay) is not bool or (prepare_relay and not prepare_worker):
        raise registration.MemberRegistrationError('relay_preparation_requires_worker_consent')
    if type(prepare_worker) is not bool or (worker_root is not None and not prepare_worker):
        raise registration.MemberRegistrationError('worker_root_consent_required')
    if prepare_worker and expected_schema != 2:
        raise registration.MemberRegistrationError('worker_root_requires_v2_invitation')
    if type(expected_schema) is not int or expected_schema not in {1, 2}:
        raise registration.MemberRegistrationError('unsupported_invitation_schema')
    if not re.fullmatch(r'[a-f0-9]{64}', invitation_sha256):
        raise registration.MemberRegistrationError('invalid_invitation_digest')
    try:
        raw = registration._read_bytes(Path(invitation_path))
        value = registration._json_document(raw)
    except (OSError, ValueError, RecursionError):
        raise registration.MemberRegistrationError('invalid_member_invitation') from None
    if hashlib.sha256(raw).hexdigest() != invitation_sha256:
        raise registration.MemberRegistrationError('invitation_changed_after_confirmation')
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != expected_schema):
        raise registration.MemberRegistrationError('invitation_changed_after_confirmation')

    if activate_tunnel and value.get('worker') is not True:
        raise registration.MemberRegistrationError('tunnel_activation_requires_worker_invitation')

    if connect_worker:
        if value.get('worker') is not True:
            raise registration.MemberRegistrationError('connect_worker_requires_worker_invitation')
        from .member_ssh_service import current_account
        current_account()  # Fail before enrollment when host identity is unsupported.

    from .node import default_node_root

    root = default_node_root()
    registration._unlinked(root)
    if expected_schema == 2:
        if install_launcher or install_startup or open_browser:
            raise registration.MemberRegistrationError('v2_gateway_options_unavailable')
        if (root / 'node.json').exists():
            raise registration.MemberRegistrationError('legacy_node_requires_review')
        result = registration.register_member(
            invitation_path, expected_invitation_sha256=invitation_sha256,
        )
        if value.get('worker') is True:
            if prepare_openssh:
                from .member_openssh_prerequisite import ensure_member_openssh
                result.update(ensure_member_openssh(state_root=Path(result['state_root']), accept_supply=True))
            from .member_transport_client import bind_member_transport
            result.update(bind_member_transport(invitation_path, state_root=Path(result['state_root']),
                expected_invitation_sha256=invitation_sha256))
            if prepare_worker:
                from .member_worker_root import prepare_worker_root
                result.update(prepare_worker_root(invitation_path, state_root=Path(result['state_root']),
                    expected_invitation_sha256=invitation_sha256, worker_root=worker_root))
                if configure_compute:
                    from .member_admission_client import configure_member_compute
                    result.update(configure_member_compute(invitation_path, state_root=Path(result['state_root']),
                        expected_invitation_sha256=invitation_sha256, interactive=True))
                if runtime_archive is not None:
                    from .member_runtime import install_member_runtime
                    installed = install_member_runtime(invitation_path, state_root=Path(result['state_root']),
                        expected_invitation_sha256=invitation_sha256, runtime_archive=runtime_archive, accept_runtime=True)
                    result.update(installed)
                    if start_supervisor:
                        from .member_supervisor_startup import start_member_supervisor
                        result.update(start_member_supervisor(installed, accept_startup=True))
                if connect_worker:
                    from .member_ssh_client import connect_member_worker
                    result.update(connect_member_worker(invitation_path, state_root=Path(result['state_root']),
                        expected_invitation_sha256=invitation_sha256, accept_connection=True))
                elif prepare_relay:
                    from .member_relay_client import prepare_member_relay
                    result.update(prepare_member_relay(invitation_path, state_root=Path(result['state_root']),
                        expected_invitation_sha256=invitation_sha256, include_activation=activate_tunnel))
                    if activate_tunnel:
                        from .member_tunnel_install import install_member_tunnel
                        result.update(install_member_tunnel(worker_root=Path(result['worker_root']),
                            machine_id=result['machine_id'], root_uuid=result['root_uuid'],
                            expected_manifest_sha256=result['relay_bundle_manifest_sha256'], accept_activation=True))
        return {**result, 'setup_flow': 'v2-registration',
                'gateway_configured': False, 'startup_installed': False,
                'launcher_installed': False, 'browser_opened': False}

    # Never erase a pending v2 identity via the legacy uninstall/replace path.
    if (root / 'member-registration').exists():
        raise registration.MemberRegistrationError('existing_v2_registration_requires_review')
    from .invitation_wizard import run_wizard

    result = run_wizard(
        invitation_path=invitation_path, install_launcher=install_launcher,
        install_startup=install_startup, open_browser=open_browser,
        expected_invitation_sha256=invitation_sha256,
    )
    return {**result, 'setup_flow': 'legacy-gateway', 'grants_execution': False}
