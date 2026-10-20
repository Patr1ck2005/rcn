"""Member installation -> dedicated local SSH -> original center acceptance handoff.

Private identity never leaves the existing signed HTTPS request. No new member,
key or admin grant on retries. Current-member tasks use least privilege; the only
local elevation is the explicit installation of Windows' dedicated sshd service.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

from . import member_registration as storage, member_admission_client as identity, ssh_identity
from .member_ssh_access import ACCESS_PATH, access_statement
from .member_ssh_bootstrap import BOOTSTRAP_PATH, bootstrap_statement
from .member_worker_root_contract import KEY_RELATIVE
from .member_ssh_service import current_account, install_service, observe_service
from .member_relay_client import prepare_member_relay
from .member_tunnel_install import install_member_tunnel
from .member_admission_contract import canonical_digest

JOURNAL='member-ssh-connection.json'


def _fail(code):
    raise storage.MemberRegistrationError(code)


def _post(c, path, statement, extra=None):
    identity._unchanged(c)
    body={'enrollment_id':c.receipt.enrollment_id,'device_credential':c.credential.get_secret_value(),
          'public_key':c.key,'signature':ssh_identity.sign(c.root/KEY_RELATIVE,statement),
          'remote_root':str(c.root),'root_uuid':c.descriptor['root_uuid'],**(extra or {})}
    result=storage._post_management(c.invitation.control_plane_url,body,path=path,
                                    timeout_s=60 if path==BOOTSTRAP_PATH else 10)
    identity._unchanged(c)
    return result


def _plan(value, c, port):
    fields={'schema_version','enrollment_id','machine_id','root_uuid','root_manifest_sha256',
            'operator_public_key','listen_address','listen_port','reverse_forward_port','registration_origin',
            'grants_execution','ssh_verified','plan_sha256'}
    if (not isinstance(value,dict) or set(value)!=fields or type(value['schema_version']) is not int or value['schema_version']!=1
            or value['enrollment_id']!=c.receipt.enrollment_id or value['machine_id']!=c.receipt.machine_id
            or value['root_uuid']!=c.descriptor['root_uuid']
            or value['root_manifest_sha256']!=canonical_digest(c.descriptor)):
        _fail('member_ssh_access_plan_invalid')
    if (value['registration_origin']!=c.invitation.control_plane_url or value['listen_address']!='127.0.0.1'
            or type(value['listen_port']) is not int or value['listen_port']!=22
            or type(value['reverse_forward_port']) is not int or value['reverse_forward_port']!=port
            or value['grants_execution'] is not False or value['ssh_verified'] is not False
            or value['operator_public_key']==c.key
            or value['plan_sha256']!=hashlib.sha256(storage._json_bytes({k:v for k,v in value.items() if k!='plan_sha256'})).hexdigest()):
        _fail('member_ssh_access_plan_invalid')
    ssh_identity.public_key(value['operator_public_key'])
    return value


def _receipt(value, c):
    fields={'bootstrap_configured','enrollment_id','machine_id','root_uuid','execution_config_sha256',
            'ssh_identity_verified_at','next_step','runtime_accepted','heartbeat_verified','grants_execution'}
    if (not isinstance(value,dict) or set(value)!=fields or value['bootstrap_configured'] is not True
            or value['enrollment_id']!=c.receipt.enrollment_id or value['machine_id']!=c.receipt.machine_id
            or value['root_uuid']!=c.descriptor['root_uuid'] or value['next_step']!='fixed_profile_acceptance'
            or not re.fullmatch(r'[a-f0-9]{64}',value['execution_config_sha256'])
            or any(value[k] is not False for k in ('runtime_accepted','heartbeat_verified','grants_execution'))):
        _fail('member_ssh_bootstrap_receipt_invalid')
    at=datetime.fromisoformat(value['ssh_identity_verified_at'])
    if at.tzinfo is None or at>datetime.now(timezone.utc):
        _fail('member_ssh_bootstrap_receipt_invalid')
    return value


def connect_member_worker(invitation_path: Path, *, state_root: Path, expected_invitation_sha256: str,
                          accept_connection: bool=False, execution_identity=None, release_descriptor=None) -> dict:
    if accept_connection is not True:
        _fail('member_ssh_connection_consent_required')
    source=Path(state_root).absolute()
    try:
        # Observe the real nonadministrator account before any local privileged action.
        if execution_identity is None:
            account=current_account()
        else:
            from .member_execution_identity import observe_identity, current_owner
            actual=observe_identity(execution_identity['root_uuid'], owner_sid=current_owner()['sid'])
            if actual != execution_identity:
                _fail('member_ssh_execution_identity_changed')
            account={'sid': actual['execution_sid'], 'username': actual['username'],
                'enabled': True, 'administrator': False, 'owner_sid': actual['owner_sid']}
        from .member_comsol_discovery import discover_comsol
        comsol=discover_comsol()
        options = {'member_account_sid':account['sid']} if execution_identity is None else {'execution_identity':execution_identity}
        relay=prepare_member_relay(invitation_path,state_root=source,
            expected_invitation_sha256=expected_invitation_sha256,include_activation=True,**options)
        storage._private_directory(source,create=False)
        with storage._exclusive(source):
            c=identity._context(Path(invitation_path),source,expected_invitation_sha256)
            plan=_plan(_post(c,ACCESS_PATH,access_statement(c.descriptor)),c,relay['reverse_forward_port'])
            path=source/JOURNAL;storage._check_private_file(path)
            old=storage._read_bytes(path) if path.exists() else None
            state=storage._json_document(old) if old is not None else None
            binding={'plan':plan,'account':account,'comsol':comsol}
            if state is None:
                state={'schema_version':1,'binding':binding,'phase':'installing','service':None,'receipt':None}
                old=storage._json_bytes(state);storage._publish(path,old)
            if (set(state)!={'schema_version','binding','phase','service','receipt'}
                    or type(state['schema_version']) is not int or state['schema_version']!=1
                    or storage._json_bytes(state['binding'])!=storage._json_bytes(binding)
                    or state['phase'] not in {'installing','installed','configured'}):
                _fail('member_ssh_connection_state_changed')
            def save(phase,service,receipt=None):
                nonlocal old
                state.update(phase=phase,service=service,receipt=receipt)
                new=storage._json_bytes(state)
                if new!=old:storage._publish(path,new,expected=old);old=new
            # Completed installs only observe. Missing or changed services are not re-created.
            if state['phase']=='installing':
                service=install_service(plan,account,state_root=source,accept_install=True)
                save('installed',service)
            else:
                service=observe_service(plan,account)
                prior=state['service']
                if ({k:v for k,v in service.items() if k!='running'}!={k:v for k,v in prior.items() if k!='running'}):
                    _fail('member_ssh_service_identity_changed')
            identity._unchanged(c)
            if not service['running']:
                return {'member_connection_state':'ssh-service-not-running','grants_execution':False}
            activation=install_member_tunnel(worker_root=c.root,machine_id=c.receipt.machine_id,
                root_uuid=c.descriptor['root_uuid'],expected_manifest_sha256=relay['relay_bundle_manifest_sha256'],accept_activation=True,
                **({'execution_identity':execution_identity,'state_root':source/'native-tunnel'} if execution_identity else {}))
            if not activation['tunnel_task_running']:
                return {**activation,'member_connection_state':'awaiting-tunnel','grants_execution':False}
            if execution_identity is not None and state['phase']=='configured':
                # The center may already have accepted/opened this machine after
                # our final response was lost. Bootstrap is a one-time handoff;
                # its original durable receipt remains the retry identity.
                receipt=_receipt(state['receipt'],c)
                identity._unchanged(c)
                return {**activation,**receipt,'member_connection_state':'awaiting-machine-acceptance',
                    'connection_configuration_preserved':True,'grants_execution':False}
            extra={'ssh_user':account['username'],'host_public_key':service['host_public_key'],
                   'comsol_root':comsol['comsol_root'],'comsol_version':comsol['comsol_version']}
            if release_descriptor is not None:
                from .member_release_catalog import approved_release_descriptor
                extra['runtime_version']=approved_release_descriptor(release_descriptor).runtime_version
            receipt=_receipt(_post(c,BOOTSTRAP_PATH,bootstrap_statement(c.descriptor,SimpleNamespace(**extra)),extra),c)
            save('configured',service,receipt)
            return {**activation,**receipt,'member_connection_state':'awaiting-machine-acceptance','grants_execution':False}
    except storage.MemberRegistrationError:
        raise
    except (OSError,ValueError,TypeError,KeyError,RuntimeError,subprocess.SubprocessError):
        _fail('member_ssh_connection_unconfirmed_preserve_identity')
