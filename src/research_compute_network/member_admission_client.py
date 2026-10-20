"""Member consent/resume over existing authenticated, fixed management routes.

Credentials remain private. A click or a saved journal never claims a machine
passed acceptance. Repeat always rechecks current center authority and offer.
"""
from __future__ import annotations

from datetime import datetime,timezone
import hashlib
from pathlib import Path
from types import SimpleNamespace

from . import member_registration as storage, member_worker_root as worker, ssh_identity
from .member_admission import (ComputeConsentRequest, ComputePreferences, OFFER_PATH, CONSENT_PATH,
    STATUS_PATH, admission_statement)
from .member_admission_contract import canonical_digest
from .admission_governance import offer_governance, TRUST_FIRST
from .member_admission_invitation import checked_offer
from .member_enrollment import MemberInvitation
from .member_worker_root_contract import KEY_RELATIVE, WorkerRootRequest, canonical_root, manifest, manifest_hash

JOURNAL='compute-consent.json'


def _fail(code):
    raise storage.MemberRegistrationError(code)


def _context(invitation_path: Path,state_root: Path,expected_invitation_sha256: str):
    raw=storage._read_bytes(invitation_path)
    if hashlib.sha256(raw).hexdigest()!=expected_invitation_sha256:
        _fail('invitation_changed_after_confirmation')
    invitation=MemberInvitation.model_validate(storage._json_document(raw))
    if not invitation.worker:
        _fail('compute_consent_requires_worker')
    receipt,credential,key,snapshots=worker._sources(state_root,invitation)
    path=state_root/worker.JOURNAL;storage._check_private_file(path)
    root_raw=storage._read_bytes(path);state=storage._json_document(root_raw)
    if (set(state)!={'schema_version','phase','manifest','marker','stage_path','source_sha256','receipt'}
            or state['phase']!='confirmed' or type(state['schema_version']) is not int or state['schema_version']!=1
            or state['source_sha256']!={name:hashlib.sha256(data).hexdigest() for name,data in snapshots.items()}):
        _fail('compute_requires_prepared_worker_root')
    descriptor=state['manifest'];root=Path(canonical_root(descriptor['remote_root']))
    expected=manifest(receipt,key,invitation.control_plane_url,str(root),descriptor['root_uuid'])
    if canonical_digest(descriptor)!=canonical_digest(expected):
        _fail('compute_root_context_changed')
    worker._receipt(state['receipt'],descriptor)
    marker=state['marker']
    if (set(marker)!={'schema_version','machine_id','root_uuid','created_at'}
            or type(marker['schema_version']) is not int or marker['schema_version']!=1
            or marker['machine_id']!=receipt.machine_id or marker['root_uuid']!=descriptor['root_uuid']):
        _fail('compute_root_context_changed')
    payloads=worker._payloads(descriptor,marker,snapshots,key)
    worker._inventory(root,payloads,strict=False)
    return SimpleNamespace(invitation=invitation,receipt=receipt,credential=credential,key=key,
        snapshots=snapshots,root=root,descriptor=descriptor,root_raw=root_raw,payloads=payloads,source=state_root)


def _unchanged(c):
    worker._check_sources(c.source,c.snapshots)
    storage._check_private_file(c.source/worker.JOURNAL)
    if storage._read_bytes(c.source/worker.JOURNAL)!=c.root_raw:
        _fail('compute_root_state_changed')
    worker._inventory(c.root,c.payloads,strict=False)


def _request(c,purpose,*,offer_sha256=None,preferences=None):
    message=admission_statement(purpose,c.descriptor,offer_sha256=offer_sha256,preferences=preferences)
    request={'enrollment_id':c.receipt.enrollment_id,'device_credential':c.credential.get_secret_value(),
        'public_key':c.key,'signature':ssh_identity.sign(c.root/KEY_RELATIVE,message),
        'remote_root':str(c.root),'root_uuid':c.descriptor['root_uuid']}
    if purpose=='consent':request.update(offer_sha256=offer_sha256,preferences=preferences,accept_compute=True)
    path={'offer':OFFER_PATH,'consent':CONSENT_PATH,'status':STATUS_PATH}[purpose]
    _unchanged(c)
    response=storage._post_management(c.invitation.control_plane_url,request,path=path)
    _unchanged(c)
    return response


def _offer(response,c):
    if not isinstance(response,dict) or set(response)!={'offer','requires_owner_consent','grants_execution'}:
        _fail('compute_offer_mismatch')
    if response['offer'] is None:
        if response['requires_owner_consent'] is not False or response['grants_execution'] is not False:
            _fail('compute_offer_mismatch')
        return None
    if response['requires_owner_consent'] is not True or response['grants_execution'] is not False:
        _fail('compute_offer_mismatch')
    offer=response['offer']
    if not isinstance(offer,dict):_fail('compute_offer_mismatch')
    proxy=SimpleNamespace(conditional_admission_offer=offer,enrollment_id=c.receipt.enrollment_id,
        invited_machine_id=c.receipt.machine_id,owner_user_id=c.receipt.owner_user_id,issued_by=offer.get('issued_by'))
    try:checked_offer(proxy)
    except (ValueError,RuntimeError):_fail('compute_offer_mismatch')
    return offer


def configure_member_compute(invitation_path: Path, *, state_root: Path, expected_invitation_sha256: str,
        preferences: dict | None=None, confirm_offer_sha256: str | None=None, accept_compute: bool=False,
        interactive: bool=False) -> dict:
    """Collect explicit consent once, persist before sending, then resume exact data."""
    source=Path(state_root).absolute()
    try:
        storage._private_directory(source,create=False)
        with storage._exclusive(source):
            c=_context(Path(invitation_path),source,expected_invitation_sha256)
            offer=_offer(_request(c,'offer'),c)
            path=source/JOURNAL;storage._check_private_file(path)
            old=storage._read_bytes(path) if path.exists() else None
            if offer is None:
                if old is not None or accept_compute or preferences is not None or confirm_offer_sha256 is not None:
                    _fail('compute_invitation_has_no_conditional_offer')
                return {'compute_consent_recorded':False,'grants_execution':False,'state':'registration_only'}
            if old is not None:
                saved=storage._json_document(old)
                if (set(saved)!={'schema_version','phase','offer_sha256','root_manifest_sha256','preferences','receipt'}
                        or type(saved['schema_version']) is not int or saved['schema_version']!=1
                        or saved['phase'] not in {'confirmed-locally','recorded'}
                        or saved['offer_sha256']!=offer['offer_sha256']
                        or saved['root_manifest_sha256']!=manifest_hash(c.descriptor)):
                    _fail('compute_consent_requires_review')
                if preferences is not None and canonical_digest(preferences)!=canonical_digest(saved['preferences']):
                    _fail('compute_consent_changed_requires_owner_settings')
                preferences=saved['preferences']
            else:
                if interactive:
                    if accept_compute or preferences is not None or confirm_offer_sha256 is not None:
                        _fail('compute_consent_modes_conflict')
                    from .member_compute_dialog import show_compute_dialog
                    facts=storage._json_document(c.snapshots['registration.json'])['request']['facts']
                    preferences=show_compute_dialog(offer,facts)
                    if preferences is None:
                        return {'compute_consent_recorded':False,'grants_execution':False,'state':'paused_by_owner_choice'}
                    confirm_offer_sha256=offer['offer_sha256'];accept_compute=True
                if accept_compute is not True or confirm_offer_sha256!=offer['offer_sha256'] or preferences is None:
                    _fail('explicit_compute_consent_required')
                preferences=ComputePreferences.model_validate(preferences).model_dump(mode='json')
                saved={'schema_version':1,'phase':'confirmed-locally','offer_sha256':offer['offer_sha256'],
                    'root_manifest_sha256':manifest_hash(c.descriptor),'preferences':preferences,'receipt':None}
                _unchanged(c)
                old=storage._json_bytes(saved);storage._publish(path,old)
            normalized=ComputePreferences.model_validate(preferences).model_dump(mode='json')
            if canonical_digest(normalized)!=canonical_digest(preferences):_fail('compute_preferences_changed')
            body={'enrollment_id':c.receipt.enrollment_id,'machine_id':c.receipt.machine_id,
                'root_manifest_sha256':manifest_hash(c.descriptor),'offer_sha256':offer['offer_sha256'],
                'accept_compute':True,'preferences':normalized}
            expected={'consent_recorded':True,'consent_sha256':canonical_digest(body),'grants_execution':False}
            if saved['phase']=='recorded' and canonical_digest(saved['receipt'])!=canonical_digest(expected):_fail('compute_consent_receipt_changed')
            if saved['phase']=='confirmed-locally' and saved['receipt'] is not None:_fail('compute_consent_receipt_changed')
            response=_request(c,'consent',offer_sha256=offer['offer_sha256'],preferences=normalized)
            if (not isinstance(response,dict) or canonical_digest(response)!=canonical_digest(expected)):
                _fail('compute_consent_receipt_mismatch')
            if storage._read_bytes(path)!=old:_fail('compute_consent_changed')
            saved.update(phase='recorded',receipt=response)
            updated=storage._json_bytes(saved)
            if updated!=old:storage._publish(path,updated,expected=old)
            return {'compute_consent_recorded':True,'consent_sha256':expected['consent_sha256'],
                'grants_execution':False,'state':('awaiting_machine_readiness'
                    if offer_governance(offer)==TRUST_FIRST else 'awaiting_machine_acceptance')}
    except storage.MemberRegistrationError:
        raise
    except (OSError,ValueError,TypeError,KeyError,RuntimeError):
        _fail('compute_configuration_failed')


def member_admission_status(invitation_path: Path, *, state_root: Path, expected_invitation_sha256: str) -> dict:
    source=Path(state_root).absolute()
    try:
        storage._private_directory(source,create=False)
        with storage._exclusive(source):
            c=_context(Path(invitation_path),source,expected_invitation_sha256)
            result=_request(c,'status')
            fields={'enrollment_id','machine_id','state','consent_recorded','grants_execution','historical_admission'}
            if (not isinstance(result,dict) or set(result)-{'audit_state'}!=fields
                    or ('audit_state' in result and result['audit_state'] not in {'pending','passed','failed','not_admitted'})
                    or result['enrollment_id']!=c.receipt.enrollment_id or result['machine_id']!=c.receipt.machine_id
                    or result['state'] not in {'admitted','revoked','awaiting_machine_acceptance','awaiting_machine_readiness','awaiting_owner_consent'}
                    or any(type(result[k]) is not bool for k in ('consent_recorded','grants_execution','historical_admission'))
                    or (result['grants_execution'] and (result['state']!='admitted' or not result['historical_admission']))):
                _fail('compute_status_mismatch')
            return result
    except storage.MemberRegistrationError:
        raise
    except (OSError,ValueError,TypeError,KeyError,RuntimeError):
        _fail('compute_status_unavailable')
