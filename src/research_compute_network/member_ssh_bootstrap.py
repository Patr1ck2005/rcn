"""Center-verified handoff from an installed member to fixed-profile acceptance.

Only an existing consented root and reserved localhost relay are eligible. The
request names a public host key/login, never a destination, script or passed
checklist. Remote publication has durable intent and CAS; retries keep identity.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path, PureWindowsPath
import re
import threading
from uuid import uuid4

from pydantic import Field, field_validator
from sqlalchemy import select

from . import member_registration as storage, ssh_identity
from .member_admission import MemberAdmissions, _stored_consent
from .member_admission_contract import canonical_digest
from .member_admission_invitation import checked_offer, validate_offer_scope
from .member_bootstrap_transport import (BootstrapUnavailable, SUPERVISOR_SHA256,
    inspect_bootstrap, activate_bootstrap, synchronize_bootstrap_capacity, BootstrapSshTransport)
from .member_enrollment import EnrollmentUnavailable
from .member_relay import _reservation
from .member_relay_policy import load_policy
from .member_worker_root_contract import WorkerRootRequest, TOKEN_RELATIVE
from .models import MachineExecutionConfig, MachineMode, MachinePolicy
from .repository import EnrollmentRow, MachineExecutionConfigRow, PolicyRow, RemoteRunRow
from .runtime_policy import STABLE_RUNTIME_VERSION
from .member_release_catalog import release_for_runtime, selected_center_release
from .schedulers.ssh import OpenSshTransport
from .supervisor_paths import LOCATION_KEY, MANAGED_LOCATION

BOOTSTRAP_PATH = '/v1/member-enrollment/ssh-bootstrap'
_SLOTS = threading.BoundedSemaphore(2)


def _bootstrap_config_shape(value):
    """Accept only the original disabled config's serialized field shape.

    Optional deadlines disappear when None; model retirement disappears when
    False. Accept only those neutral values, without normalizing signed bytes
    or enabling retirement as a side effect of member bootstrap.
    """
    if not isinstance(value, dict):
        return False
    deadlines = {'ssh_connect_timeout_s', 'ssh_status_timeout_s'}
    optional = deadlines | {'scientific_model_retirement_enabled'}
    fields = set(MachineExecutionConfig.model_fields)
    return (fields - optional <= set(value) <= fields
            and all(value.get(name) is None for name in deadlines)
            and value.get('scientific_model_retirement_enabled', False) is False)


class SshBootstrapRequest(WorkerRootRequest):
    ssh_user: str = Field(pattern=r'^[a-z][a-z0-9_.-]{0,31}$')
    host_public_key: str
    comsol_root: str
    comsol_version: str = '6.4'
    runtime_version: str = STABLE_RUNTIME_VERSION
    _key = field_validator('host_public_key')(ssh_identity.public_key)

    @field_validator('comsol_root')
    @classmethod
    def comsol_install_root(cls, value):
        root=PureWindowsPath(value)
        if not root.is_absolute() or '..' in root.parts or root.name.casefold()!='comsol64':
            raise ValueError('validated COMSOL64 install root required')
        return str(root)

    @field_validator('comsol_version')
    @classmethod
    def fixed_comsol_version(cls, value):
        if value!='6.4':raise ValueError('COMSOL 6.4 required')
        return value

    @field_validator('runtime_version')
    @classmethod
    def reviewed_runtime(cls, value):
        release_for_runtime(value)
        return value

    @field_validator('ssh_user')
    @classmethod
    def non_system(cls, value):
        if value in {'administrator','system','guest','defaultaccount'}:
            raise ValueError('dedicated nonadministrator SSH account required')
        return value


def bootstrap_statement(descriptor, request):
    value = {'purpose':'rcn-member-ssh-bootstrap-v1','root_manifest':descriptor,
        'ssh_user':request.ssh_user,'host_public_key':request.host_public_key,
        'comsol_root':request.comsol_root,'comsol_version':request.comsol_version}
    version = getattr(request, 'runtime_version', STABLE_RUNTIME_VERSION)
    if version != STABLE_RUNTIME_VERSION:
        value['runtime_version'] = version
    return storage._json_bytes(value)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


class MemberSshBootstrap:
    def __init__(self, repository, *, authorization_root, verification_root, transport_factory=None):
        self.repository = repository
        self.root = Path(authorization_root).absolute()
        self.admissions = MemberAdmissions(repository, verification_root=verification_root)
        self.transport_factory = transport_factory or self._transport

    def _transport(self, config):
        value = os.environ.get('RCN_SSH_IDENTITY_FILE')
        if not value or not Path(value).is_absolute():
            raise BootstrapUnavailable('member_bootstrap_operator_identity_required')
        storage._check_private_file(Path(value))
        if not Path(value).is_file():
            raise BootstrapUnavailable('member_bootstrap_operator_identity_required')
        return BootstrapSshTransport(config, state_root=self.root/'bootstrap-ssh', identity_file=value)

    def _context(self, session, request, policy):
        record, claim = self.admissions._context(session, request)
        offer = checked_offer(record)
        validate_offer_scope(session, offer)
        consent = _stored_consent(record)
        requested_runtime = getattr(request, 'runtime_version', offer['runtime_version'])
        if (requested_runtime != offer['runtime_version']
                or requested_runtime != STABLE_RUNTIME_VERSION and requested_runtime != selected_center_release().runtime_version):
            raise EnrollmentUnavailable()
        owned = MachinePolicy.model_validate(session.get(PolicyRow, record.machine_id).payload)
        if (record.member_admission_result is not None or owned.effective_mode() != MachineMode.PAUSED
                or owned.admin_mode_override is not None or owned.member_execution_limit is None
                or not owned.member_execution_limit.active or canonical_digest(owned.model_dump(mode='json')) != consent['policy_sha256']
                or policy.registration_origin != record.registration_url or not policy.admission_enabled
                or request.public_key == getattr(request, 'host_public_key', None)):
            raise EnrollmentUnavailable()
        reservation = _reservation(record, policy)
        context = {'root':canonical_digest(claim),'offer':offer['offer_sha256'],
                   'consent':consent['consent_sha256'],'policy':consent['policy_sha256'],
                   'relay':canonical_digest(reservation.model_dump(mode='json'))}
        return record, claim, reservation, context

    def _write(self, request, policy, context, action):
        def transaction():
            with self.repository._session() as session, session.begin():
                self.admissions.transport.enrollment._lock(session, request.enrollment_id)
                record, claim, reservation, latest = self._context(session, request, policy)
                if latest != context:
                    raise EnrollmentUnavailable()
                return action(session, record, claim, reservation)
        return self.repository._retry_sqlite_write(transaction)

    @staticmethod
    def _save(session, record, state):
        record.member_ssh_bootstrap = state
        session.get(EnrollmentRow, record.enrollment_id).payload = record.model_dump(mode='json')

    @staticmethod
    def _no_other_work(session, machine_id):
        # Unknown states are not terminal, including NULL/absent state metadata.
        rows = session.scalars(select(RemoteRunRow).where(RemoteRunRow.machine_id == machine_id))
        for row in rows:
            if row.payload.get('state') not in {'completed','failed','cancelled','interrupted'}:
                raise BootstrapUnavailable('member_bootstrap_pending_work')

    @staticmethod
    def _observation(value, request, claim, nonce):
        try:
            expected = {'schema_version','nonce','hostname','username','sid','administrator','config',
                        'config_sha256','supervisor_sha256','status'}
            if (set(value) != expected or type(value['schema_version']) is not int or value['schema_version'] != 1
                    or value['nonce'] != nonce or value['username'] != request.ssh_user
                    or value['administrator'] is not False or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',value['sid'])
                    or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',value['hostname'])
                    or value['supervisor_sha256'] != release_for_runtime(request.runtime_version).supervisor_sha256
                    or not re.fullmatch(r'[a-f0-9]{64}',value['config_sha256'])
                    or not _bootstrap_config_shape(value['config'])
                    or value['config']['enabled'] is not False
                    or type(value['config']['max_concurrent_units']) is not int or value['config']['max_concurrent_units'] != 1
                    or type(value['config']['target_concurrent_units']) is not int or value['config']['target_concurrent_units'] not in {0,1}):
                raise ValueError('unverified bootstrap response')
            status = value['status']; at = datetime.fromisoformat(status['updated_at'].replace('Z','+00:00'))
            if (at.tzinfo is None or not 0 <= (datetime.now(timezone.utc)-at).total_seconds() <= 30
                    or status['machine_id'] != claim['machine_id'] or status['root_uuid'] != claim['root_uuid']
                    or status['runtime_version'] != request.runtime_version or status['active_run_ids'] != []
                    or type(status['pid']) is not int or status['pid'] <= 0
                    or type(status['max_concurrent_units']) is not int or status['max_concurrent_units'] not in {0,1}):
                raise ValueError('invalid bootstrap supervisor observation')
            return MachineExecutionConfig.model_validate(value['config'])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise BootstrapUnavailable('member_bootstrap_identity_not_verified') from None

    @staticmethod
    def _validate_saved(saved, request, claim, route, context):
        try:
            fields = {'schema_version','request_sha256','context','nonce','phase','snapshot','receipt'}
            if (set(saved) not in (fields, fields | {'capacity_authority'})
                    or type(saved['schema_version']) is not int or saved['schema_version'] != 1
                    or saved['request_sha256'] != _sha(bootstrap_statement(claim,request))
                    or saved['context'] != context or not re.fullmatch(r'[a-f0-9]{32}',saved['nonce'])
                    or saved['phase'] not in {'inspecting','publishing','configured'}):
                raise ValueError('intent changed')
            if 'capacity_authority' in saved:
                authority = saved['capacity_authority']
                created = datetime.fromisoformat(authority['created_at'])
                expires = datetime.fromisoformat(authority['expires_at'])
                if (set(authority) != {'created_at','expires_at'} or created.tzinfo is None
                        or expires.tzinfo is None or created > datetime.now(timezone.utc)
                        or expires-created != timedelta(minutes=5) or saved['phase']=='inspecting'):
                    raise ValueError('capacity authority changed')
            if saved['phase']=='inspecting':
                if saved['snapshot'] is not None or saved['receipt'] is not None:raise ValueError('premature receipt')
                return
            snap=saved['snapshot']
            if (set(snap) != {'before_sha256','desired','after_sha256','sid'}
                    or not re.fullmatch(r'[a-f0-9]{64}',snap['before_sha256'])
                    or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',snap['sid'])
                    or _sha(storage._json_bytes(snap['desired'])) != snap['after_sha256']):
                raise ValueError('snapshot changed')
            cfg=snap['desired'];root=PureWindowsPath(claim['remote_root'])
            required={'machine_id':claim['machine_id'],'root_uuid':claim['root_uuid'],'remote_root':str(root),
                'python_executable':str(root.parent/'runtime/python/python.exe'),'runtime_version':request.runtime_version,
                'ssh_host':'127.0.0.1','ssh_port':route.ssh_port,'ssh_user':request.ssh_user,'pinned_host_key':route.pinned_host_key,
                'machine_token_file':str(root/TOKEN_RELATIVE),'control_plane_heartbeat_url':claim['control_plane_heartbeat_url'],
                'comsol_root':request.comsol_root,'comsol_version':request.comsol_version}
            if (not _bootstrap_config_shape(cfg) or any(cfg[k]!=v for k,v in required.items())
                    or cfg['enabled'] is not False or type(cfg['target_concurrent_units']) is not int or cfg['target_concurrent_units']!=1
                    or type(cfg['max_concurrent_units']) is not int or cfg['max_concurrent_units']!=1
                    or cfg['execution_provenance'] != {LOCATION_KEY:MANAGED_LOCATION,'member_bootstrap_stage':'acceptance',
                                                       'member_bootstrap_root_sha256':canonical_digest(claim)}):
                raise ValueError('unsafe desired configuration')
            receipt=saved['receipt']
            if saved['phase']=='publishing':
                if receipt is not None:raise ValueError('premature completion')
            else:
                expected={'bootstrap_configured':True,'enrollment_id':request.enrollment_id,'machine_id':claim['machine_id'],
                    'root_uuid':claim['root_uuid'],'execution_config_sha256':canonical_digest(cfg),
                    'next_step':'fixed_profile_acceptance','runtime_accepted':False,'heartbeat_verified':False,'grants_execution':False}
                if (set(receipt)!=set(expected)|{'ssh_identity_verified_at'}
                        or storage._json_bytes({k:receipt[k] for k in expected})!=storage._json_bytes(expected)
                        or datetime.fromisoformat(receipt['ssh_identity_verified_at']).tzinfo is None):
                    raise ValueError('invalid historical receipt')
        except (ValueError,TypeError,KeyError,AttributeError):
            raise BootstrapUnavailable('member_bootstrap_intent_conflict') from None

    def confirm(self, request):
        request = SshBootstrapRequest.model_validate(request.model_dump())
        if not _SLOTS.acquire(blocking=False):
            raise BootstrapUnavailable('member_bootstrap_busy_retry_same_identity')
        try:
            return self._confirm(request)
        finally:
            _SLOTS.release()

    def _confirm(self, request):
        # Authority and signature precede any SSH connection or durable bootstrap write.
        policy = load_policy(self.root)
        with self.repository._session() as session:
            record, claim, reservation, context = self._context(session, request, policy)
        self.admissions.transport.verify_possession(request, bootstrap_statement(claim,request))
        request_hash = _sha(bootstrap_statement(claim,request))
        route = MachineExecutionConfig(machine_id=record.machine_id, remote_root=claim['remote_root'],
            root_uuid=claim['root_uuid'], ssh_host='127.0.0.1',ssh_port=reservation.listener_port,
            ssh_user=request.ssh_user,runtime_version=request.runtime_version,
            pinned_host_key=f'[127.0.0.1]:{reservation.listener_port} {request.host_public_key}')

        def reserve(session, current, root_claim, relay):
            saved = current.member_ssh_bootstrap
            if saved is not None:
                self._validate_saved(saved,request,claim,route,context)
                return saved
            if session.get(MachineExecutionConfigRow,current.machine_id) is not None:
                raise BootstrapUnavailable('member_bootstrap_existing_config_requires_migration')
            self._no_other_work(session,current.machine_id)
            saved = {'schema_version':1,'request_sha256':request_hash,'context':context,
                     'nonce':uuid4().hex,'phase':'inspecting','snapshot':None,'receipt':None}
            self._save(session,current,saved)
            return saved
        state = self._write(request,policy,context,reserve)
        if state['phase'] == 'configured':
            def existing(session,current,*_):
                row = session.get(MachineExecutionConfigRow,current.machine_id)
                snapshot = current.member_ssh_bootstrap['snapshot']
                if row is None or canonical_digest(row.payload) != canonical_digest(snapshot['desired']):
                    raise BootstrapUnavailable('member_bootstrap_configuration_advanced')
                return current.member_ssh_bootstrap['receipt']
            return self._write(request,policy,context,existing)
        transport = self.transport_factory(route)
        observed = inspect_bootstrap(transport,route,state['nonce'])
        actual = self._observation(observed,request,claim,state['nonce'])
        if state['phase'] == 'inspecting':
            root = PureWindowsPath(claim['remote_root'])
            expected = MachineExecutionConfig(machine_id=record.machine_id,remote_root=str(root),
                root_uuid=claim['root_uuid'],python_executable=str(root.parent/'runtime/python/python.exe'),
                runtime_version=request.runtime_version,enabled=False,max_concurrent_units=1,target_concurrent_units=0,
                supervisor_startup='logon',control_plane_heartbeat_url=record.registration_url,
                machine_token_file=str(root/TOKEN_RELATIVE),tunnel_task_name='RCN-Member-'+claim['root_uuid'],
                updated_at=actual.updated_at)
            if canonical_digest(actual.model_dump(mode='json')) != canonical_digest(expected.model_dump(mode='json')):
                raise BootstrapUnavailable('member_bootstrap_not_original_zero_configuration')
            desired = actual.model_dump(mode='json')
            desired.update(ssh_host=route.ssh_host,ssh_port=route.ssh_port,ssh_user=route.ssh_user,
                pinned_host_key=route.pinned_host_key,target_concurrent_units=1,expected_hostname=observed['hostname'],
                comsol_root=request.comsol_root,comsol_version=request.comsol_version,
                coordinator_host=policy.coordinator_host,coordinator_port=policy.coordinator_port,
                coordinator_user=policy.coordinator_user,reverse_forward_port=reservation.listener_port,
                execution_provenance={LOCATION_KEY:MANAGED_LOCATION,'member_bootstrap_stage':'acceptance',
                    'member_bootstrap_root_sha256':canonical_digest(claim)})
            snapshot = {'before_sha256':observed['config_sha256'],'desired':desired,
                        'after_sha256':_sha(storage._json_bytes(desired)),'sid':observed['sid']}
            def prepare(session,current,*_):
                self._no_other_work(session,current.machine_id)
                saved = current.member_ssh_bootstrap
                if saved['phase'] != 'inspecting':
                    if saved['snapshot'] != snapshot:
                        raise BootstrapUnavailable('member_bootstrap_snapshot_conflict')
                    return saved
                saved = {**saved,'snapshot':snapshot,'phase':'publishing'}
                self._save(session,current,saved)
                return saved
            state = self._write(request,policy,context,prepare)
        snapshot = state['snapshot']
        if (observed['config_sha256'] not in {snapshot['before_sha256'],snapshot['after_sha256']}
                or observed['sid'] != snapshot['sid']):
            raise BootstrapUnavailable('member_bootstrap_remote_configuration_changed')
        # Recheck invitation/owner/consent immediately before the only remote write.
        if load_policy(self.root) != policy:
            raise BootstrapUnavailable('member_bootstrap_relay_policy_changed')
        self._write(request,policy,context,lambda session,current,*_: self._no_other_work(session,current.machine_id))
        verified = activate_bootstrap(transport,route,state['nonce'],snapshot['before_sha256'],snapshot['desired'])
        self._observation(verified,request,claim,state['nonce'])
        if (verified['config_sha256'] != snapshot['after_sha256']
                or canonical_digest(verified['config']) != canonical_digest(snapshot['desired'])
                or verified['sid'] != snapshot['sid']):
            raise BootstrapUnavailable('member_bootstrap_publication_not_verified')
        consent=_stored_consent(record);offer=checked_offer(record)
        authority = {'created_at':consent['recorded_at'], 'expires_at':offer['expires_at']}
        if offer['expires_at'] is None:
            # A lasting compute grant never makes a remote command nonce lasting.
            # Persist the short command lease before publication; retries reuse it.
            def capacity_authority(session,current,*_):
                saved = current.member_ssh_bootstrap
                if 'capacity_authority' not in saved:
                    now = datetime.now(timezone.utc)
                    saved = {**saved, 'capacity_authority': {'created_at':now.isoformat(),
                        'expires_at':(now+timedelta(minutes=5)).isoformat()}}
                    self._save(session,current,saved)
                return saved['capacity_authority']
            authority = self._write(request,policy,context,capacity_authority)
        synchronize_bootstrap_capacity(transport,MachineExecutionConfig.model_validate(snapshot['desired']),
            operation_nonce=state['nonce'],**authority)

        def finish(session,current,*_):
            self._no_other_work(session,current.machine_id)
            saved = current.member_ssh_bootstrap
            if saved['snapshot'] != snapshot:
                raise BootstrapUnavailable('member_bootstrap_snapshot_changed')
            existing = session.get(MachineExecutionConfigRow,current.machine_id)
            if existing is not None:
                if saved['phase'] == 'configured' and canonical_digest(existing.payload) == canonical_digest(snapshot['desired']):
                    return saved['receipt']
                raise BootstrapUnavailable('member_bootstrap_existing_config_requires_migration')
            receipt = {'bootstrap_configured':True,'enrollment_id':current.enrollment_id,'machine_id':current.machine_id,
                'root_uuid':claim['root_uuid'],'execution_config_sha256':canonical_digest(snapshot['desired']),
                'ssh_identity_verified_at':datetime.now(timezone.utc).isoformat(),
                'next_step':'fixed_profile_acceptance','runtime_accepted':False,'heartbeat_verified':False,'grants_execution':False}
            session.add(MachineExecutionConfigRow(machine_id=current.machine_id,payload=snapshot['desired']))
            self._save(session,current,{**saved,'phase':'configured','receipt':receipt})
            self.admissions.transport.enrollment._audit(session,'member.ssh_bootstrap_configured',
                f'machine-agent:{current.machine_id}',current.enrollment_id,
                machine_id=current.machine_id,root_uuid=claim['root_uuid'],
                execution_config_sha256=receipt['execution_config_sha256'],grants_execution=False)
            return receipt
        return self._write(request,policy,context,finish)
