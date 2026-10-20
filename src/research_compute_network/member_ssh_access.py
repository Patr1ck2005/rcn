"""Authenticated distribution of the center's public ingress key, never a secret.

Reuses invitation, root, relay and owner-consent checks. A returned access plan is
not an SSH/runtime/compute acceptance result. No OS objects are changed here.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from . import member_registration as storage, ssh_identity
from .member_bootstrap_transport import BootstrapUnavailable
from .member_ssh_bootstrap import MemberSshBootstrap
from .member_relay_policy import load_policy

ACCESS_PATH = '/v1/member-enrollment/ssh-access-plan'


def access_statement(descriptor: dict) -> bytes:
    return storage._json_bytes({'purpose':'rcn-member-ssh-access-plan-v1','root_manifest':descriptor})


def operator_public_key() -> str:
    value = os.environ.get('RCN_SSH_IDENTITY_FILE')
    if not value or not Path(value).is_absolute():
        raise BootstrapUnavailable('member_bootstrap_operator_identity_required')
    path = Path(value)
    storage._check_private_file(path)
    raw = storage._read_bytes(path)
    key = ssh_identity.derive_public(path)
    storage._check_private_file(path)
    if storage._read_bytes(path) != raw:
        raise BootstrapUnavailable('member_bootstrap_operator_identity_changed')
    return key


class MemberSshAccess:
    def __init__(self, repository, *, authorization_root, verification_root):
        self.bootstrap = MemberSshBootstrap(repository, authorization_root=authorization_root,
                                             verification_root=verification_root)
        self.repository = repository

    def plan(self, request) -> dict:
        manager = self.bootstrap
        policy = load_policy(manager.root)
        with self.repository._session() as session:
            record, claim, relay, context = manager._context(session, request, policy)
        manager.admissions.transport.verify_possession(request, access_statement(claim))
        key = operator_public_key()
        if key == request.public_key or key == policy.host_public_key:
            raise BootstrapUnavailable('member_ssh_access_key_roles_must_be_separate')
        # Recheck authority after key inspection; no secret, identity key or path is returned.
        with self.repository._session() as session:
            current, latest, current_relay, current_context = manager._context(session, request, policy)
            if latest != claim or current_context != context:
                raise BootstrapUnavailable('member_ssh_access_authority_changed')
        if load_policy(manager.root) != policy or operator_public_key() != key:
            raise BootstrapUnavailable('member_ssh_access_operator_policy_changed')
        plan = {'schema_version':1, 'enrollment_id':record.enrollment_id,'machine_id':record.machine_id,
                'root_uuid':claim['root_uuid'],'root_manifest_sha256':context['root'],
                'operator_public_key':key,'listen_address':'127.0.0.1','listen_port':22,
                'reverse_forward_port':relay.listener_port,'registration_origin':record.registration_url,
                'grants_execution':False,'ssh_verified':False}
        return {**plan,'plan_sha256':hashlib.sha256(storage._json_bytes(plan)).hexdigest()}
