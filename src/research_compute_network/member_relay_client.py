"""Consume a center-approved relay and prepare the existing coordinated guard.

No OS tasks are registered, no SSH/service is started and no computation is
opened. The member never supplies the relay account, ingress key or listen port.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

from . import member_registration as storage, member_worker_root as worker, ssh_identity
from .member_enrollment import MemberInvitation
from .member_relay import RELAY_PATH, RelayRequest, relay_statement
from .member_relay_policy import RelayPolicy
from .member_worker_root_contract import (KEY_RELATIVE, TOKEN_RELATIVE, canonical_root, manifest, manifest_hash)
from .models import MachineExecutionConfig
from .tunnel import build_coordinated_tunnel_bundle, coordinated_bundle_files

JOURNAL = 'relay-setup.json'
_FIELDS = {'schema_version','enrollment_id','machine_id','root_manifest_sha256','policy_sha256','endpoint_id',
    'coordinator_host','coordinator_port','coordinator_user','host_public_key','reverse_forward_bind',
    'reverse_forward_port','reverse_target_host','reverse_target_port','relay_key_published',
    'new_connection_authorization_expires_at','ssh_verified','heartbeat_verified','runtime_accepted',
    'existing_sessions_revoked','grants_execution'}


def _fail(code):
    raise storage.MemberRegistrationError(code)


def _plan(value, descriptor):
    import re
    try:
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise ValueError('incomplete relay receipt')
        if (type(value['schema_version']) is not int or value['schema_version'] != 1
                or value['enrollment_id'] != descriptor['enrollment_id'] or value['machine_id'] != descriptor['machine_id']
                or value['root_manifest_sha256'] != manifest_hash(descriptor)
                or value['relay_key_published'] is not True
                or any(value[name] is not False for name in ('ssh_verified','heartbeat_verified','runtime_accepted','existing_sessions_revoked','grants_execution'))
                or value['reverse_forward_bind'] != 'localhost' or value['reverse_target_host'] != '127.0.0.1'
                or type(value['reverse_target_port']) is not int or value['reverse_target_port'] != 22
                or not re.fullmatch(r'[a-f0-9]{64}', value['policy_sha256'])
                or not re.fullmatch(r'rcn_[a-z0-9_]{1,27}', value['coordinator_user'])):
            raise ValueError('relay binding mismatch')
        for field, minimum in (('coordinator_port',1), ('reverse_forward_port',1024)):
            if type(value[field]) is not int or not minimum <= value[field] <= 65535:
                raise ValueError('invalid port')
        RelayPolicy.host(value['coordinator_host'])
        ssh_identity.public_key(value['host_public_key'])
        expires = datetime.fromisoformat(value['new_connection_authorization_expires_at'])
        if expires.tzinfo is None or not 0 < (expires-datetime.now(timezone.utc)).total_seconds() <= 360:
            raise ValueError('expired relay lease')
        return {name: value[name] for name in ('endpoint_id','policy_sha256','coordinator_host',
            'coordinator_port','coordinator_user','host_public_key','reverse_forward_port')}
    except (ValueError, TypeError, KeyError):
        _fail('member_relay_receipt_mismatch')


def prepare_member_relay(invitation_path: Path, *, state_root: Path, expected_invitation_sha256: str,
                         include_activation: bool = False, member_account_sid: str | None = None,
                         execution_identity=None) -> dict:
    if type(include_activation) is not bool:
        _fail('explicit_tunnel_activation_mode_required')
    try:
        raw = storage._read_bytes(Path(invitation_path))
        if hashlib.sha256(raw).hexdigest() != expected_invitation_sha256:
            _fail('invitation_changed_after_confirmation')
        invitation = MemberInvitation.model_validate(storage._json_document(raw))
        source = Path(state_root).absolute()
        storage._private_directory(source, create=False)
        with storage._exclusive(source):
            registered, credential, key, snapshots = worker._sources(source, invitation)
            root_state_path = source / worker.JOURNAL
            storage._check_private_file(root_state_path)
            root_raw = storage._read_bytes(root_state_path)
            root_state = storage._json_document(root_raw)
            if (set(root_state) != {'schema_version','phase','manifest','marker','stage_path','source_sha256','receipt'}
                    or type(root_state['schema_version']) is not int or root_state['schema_version'] != 1
                    or root_state['source_sha256'] != {name:hashlib.sha256(data).hexdigest() for name,data in snapshots.items()}
                    or root_state['phase'] != 'confirmed'):
                _fail('member_relay_requires_prepared_root')
            descriptor = root_state['manifest']
            root = Path(canonical_root(descriptor['remote_root']))
            expected = manifest(registered, key, invitation.control_plane_url, str(root), descriptor['root_uuid'])
            if storage._json_bytes(descriptor) != storage._json_bytes(expected):
                _fail('member_relay_root_identity_changed')
            worker._receipt(root_state['receipt'], descriptor)
            marker = root_state['marker']
            if (set(marker) != {'schema_version','machine_id','root_uuid','created_at'}
                    or type(marker['schema_version']) is not int or marker['schema_version'] != 1
                    or marker['machine_id'] != registered.machine_id or marker['root_uuid'] != descriptor['root_uuid']):
                _fail('member_relay_root_identity_changed')
            payloads = worker._payloads(descriptor, root_state['marker'], snapshots, key)
            worker._inventory(root, payloads, strict=False)
            proof = ssh_identity.sign(root / KEY_RELATIVE, relay_statement(descriptor))
            request = RelayRequest(enrollment_id=registered.enrollment_id, device_credential=credential,
                public_key=key, signature=proof, remote_root=str(root), root_uuid=descriptor['root_uuid'])
            response = storage._post_management(invitation.control_plane_url,
                {**request.model_dump(mode='json'), 'device_credential':credential.get_secret_value()}, path=RELAY_PATH)
            plan = _plan(response, descriptor)
            worker._check_sources(source, snapshots)
            if storage._read_bytes(root_state_path) != root_raw:
                _fail('member_relay_root_state_changed')
            worker._inventory(root, payloads, strict=False)
            known_hosts = root / 'agent/tunnel/known_hosts'
            hostname = plan['coordinator_host'] if plan['coordinator_port'] == 22 else f"[{plan['coordinator_host']}]:{plan['coordinator_port']}"
            config = MachineExecutionConfig(machine_id=registered.machine_id, root_uuid=descriptor['root_uuid'],
                remote_root=str(root), enabled=False, target_concurrent_units=0, tunnel_startup='boot',
                coordinator_host=plan['coordinator_host'], coordinator_port=plan['coordinator_port'],
                coordinator_user=plan['coordinator_user'], reverse_forward_host='127.0.0.1',
                reverse_forward_port=plan['reverse_forward_port'],
                tunnel_task_name='RCN-Member-' + descriptor['root_uuid'],
                machine_token_file=str(root/TOKEN_RELATIVE), control_plane_heartbeat_url=invitation.control_plane_url)
            relay_identity = root/'agent/tunnel/execution/member_ed25519' if execution_identity is not None else root/KEY_RELATIVE
            bundle = build_coordinated_tunnel_bundle(config, identity_file=str(relay_identity), known_hosts_file=str(known_hosts))
            if execution_identity is not None:
                from .member_tunnel_identity import execution_bundle
                bundle = execution_bundle(bundle, execution_identity)
            elif member_account_sid is not None:
                from .member_tunnel_identity import member_bundle
                bundle = member_bundle(bundle, member_account_sid)
            journal = source / JOURNAL
            storage._check_private_file(journal)
            saved = storage._read_bytes(journal) if journal.exists() else None
            bundle_activation = include_activation
            if saved is not None and not include_activation:
                # Retry keeps an already selected richer bundle. This selects only
                # exact known generator bytes; it never executes saved code.
                prior = storage._json_document(saved)
                if (not isinstance(prior, dict) or not isinstance(prior.get('identity'), dict)
                        or not isinstance(prior['identity'].get('files_sha256'), dict)):
                    _fail('member_relay_configuration_changed_requires_migration')
                candidate = coordinated_bundle_files(bundle, include_activation=True)
                expected_installer = hashlib.sha256(candidate['install-coordinated-tunnel.ps1']).hexdigest()
                bundle_activation = prior.get('identity', {}).get('files_sha256', {}).get('relay-bundle/install-coordinated-tunnel.ps1') == expected_installer
            generated = coordinated_bundle_files(bundle, include_activation=bundle_activation)
            leaves = {'known_hosts': (hostname+' '+plan['host_public_key']+'\n').encode('ascii'),
                      'relay-plan.json': storage._json_bytes({'schema_version':1,'root_manifest_sha256':manifest_hash(descriptor),**plan})}
            leaves.update({'relay-bundle/'+name:data for name,data in generated.items()})
            identity = {'schema_version':1,'root_manifest_sha256':manifest_hash(descriptor),'plan':plan,
                        'files_sha256':{name:hashlib.sha256(data).hexdigest() for name,data in leaves.items()}}
            destination = root / 'agent/tunnel'
            already_ready = False
            if saved is not None:
                value = storage._json_document(saved)
                if (set(value) != {'phase','identity'} or value.get('phase') not in {'prepared','ready'}
                        or storage._json_bytes(value.get('identity')) != storage._json_bytes(identity)):
                    _fail('member_relay_configuration_changed_requires_migration')
                already_ready = value['phase'] == 'ready'
            else:
                if any((destination/name).exists() for name in leaves):
                    _fail('member_relay_unowned_configuration')
                saved = storage._json_bytes({'phase':'prepared','identity':identity})
                storage._publish(journal,saved)
            storage._private_directory(destination/'relay-bundle', create=not already_ready)
            if not already_ready:
                for name,data in leaves.items():
                    # Same-root, fixed names; only an incomplete preparation resumes.
                    # A completed bundle is read-only on retry. Manifest is last.
                    worker._publish_leaf(destination/name,data,maximum=262144)
            for name,data in leaves.items():
                storage._check_private_file(destination/name)
                if storage._read_bytes(destination/name,maximum=262144)!=data:
                    _fail('member_relay_file_readback_failed')
            worker._check_sources(source, snapshots)
            if storage._read_bytes(root_state_path) != root_raw:
                _fail('member_relay_root_state_changed')
            worker._inventory(root, payloads, strict=False)
            done = storage._json_bytes({'phase':'ready','identity':identity})
            if saved != done:
                storage._publish(journal,done,expected=saved)
            return {'relay_bootstrap_prepared':True,'relay_key_published':True,
                    'reverse_forward_port':plan['reverse_forward_port'],
                    'relay_bundle_path':str(destination/'relay-bundle'),
                    'relay_bundle_manifest_sha256':hashlib.sha256(generated['manifest.json']).hexdigest(),
                    'tunnel_tasks_installed':False,'ssh_verified':False,
                    'heartbeat_verified':False,'grants_execution':False}
    except storage.MemberRegistrationError:
        raise
    except (OSError,ValueError,TypeError,KeyError,RuntimeError):
        _fail('member_relay_preparation_failed')
