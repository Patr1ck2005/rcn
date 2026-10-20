"""Transactional, administrator-owned scope snapshot for one invitation."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .member_admission_contract import ConditionalAdmissionRequest, canonical_digest
from .member_enrollment import EnrollmentUnavailable
from .models import ExecutionProfile, ProjectGrant, ProjectStatus
from .repository import ProfileRow, ProjectGrantRow
from .runtime_policy import STABLE_RUNTIME_VERSION
from .member_release_catalog import selected_center_release, release_for_runtime


def validate_scope(session, request: ConditionalAdmissionRequest) -> None:
    from .repository import UserRow
    from .models import UserAccount, UserRole
    for person_id, profiles in request.person_profiles.items():
        user_row = session.get(UserRow, person_id)
        user = UserAccount.model_validate(user_row.payload) if user_row is not None else None
        if user is None or not user.active or not (user.roles & {UserRole.MEMBER, UserRole.ADMIN}):
            raise EnrollmentUnavailable()
        for profile_id in profiles:
            row = session.get(ProfileRow, profile_id)
            if row is None:
                raise EnrollmentUnavailable()
            profile = ExecutionProfile.model_validate(row.payload)
            if profile.allow_arbitrary_command or "windows" not in profile.platforms:
                raise EnrollmentUnavailable()
    for project_id, profiles in request.project_profiles.items():
        row = session.get(ProjectGrantRow, project_id)
        if row is None or not row.approved:
            raise EnrollmentUnavailable()
        grant = ProjectGrant.model_validate(row.payload)
        if (grant.project_id != project_id or not grant.approved or grant.status != ProjectStatus.ACTIVE
                or not set(profiles).issubset(grant.allowed_profiles)
                or (grant.trusted_machine_labels and not request.acknowledge_project_trust)):
            raise EnrollmentUnavailable()
        for profile_id in profiles:
            row = session.get(ProfileRow, profile_id)
            if row is None:
                raise EnrollmentUnavailable()
            profile = ExecutionProfile.model_validate(row.payload)
            if (profile.profile_id != profile_id or profile.allow_arbitrary_command
                    or 'windows' not in profile.platforms):
                raise EnrollmentUnavailable()


def make_offer(session, request: ConditionalAdmissionRequest, *, enrollment_id: str,
               machine_id: str, owner_user_id: str, actor_id: str, now: datetime) -> dict:
    selected_center_release().require_configured()
    validate_scope(session, request)
    trust = {key: sorted(ProjectGrant.model_validate(session.get(ProjectGrantRow,key).payload).trusted_machine_labels)
        for key in request.project_profiles}
    value = {'schema_version': 1, 'enrollment_id': enrollment_id, 'machine_id': machine_id,
        'owner_user_id': owner_user_id, 'issued_by': actor_id,
        'scope': request.model_dump(mode='json'), 'runtime_version': selected_center_release().runtime_version,
        'project_trust_labels': trust,
        'created_at': now.isoformat(), 'expires_at': (
            None if request.valid_for_days is None else (now+timedelta(days=request.valid_for_days)).isoformat())}
    offered = {**value, 'offer_sha256': canonical_digest(value)}
    import json
    if len(json.dumps(offered, ensure_ascii=True).encode('ascii')) > 12288:
        raise EnrollmentUnavailable()  # bounded offer must fit the unchanged HTTPS response envelope
    return offered


def validate_offer_scope(session, offer: dict) -> None:
    request = ConditionalAdmissionRequest.model_validate(offer['scope'])
    validate_scope(session, request)
    for project, labels in offer['project_trust_labels'].items():
        current = ProjectGrant.model_validate(session.get(ProjectGrantRow,project).payload)
        if sorted(current.trusted_machine_labels) != labels:
            raise EnrollmentUnavailable()


def checked_offer(record, *, now: datetime | None = None) -> dict:
    value = record.conditional_admission_offer
    try:
        required = {'schema_version','enrollment_id','machine_id','owner_user_id','issued_by',
                    'scope','runtime_version','project_trust_labels','created_at','expires_at','offer_sha256'}
        if not isinstance(value, dict) or set(value) != required or type(value['schema_version']) is not int or value['schema_version'] != 1:
            raise ValueError('invalid offer')
        scope = ConditionalAdmissionRequest.model_validate(value['scope'])
        trust = value['project_trust_labels']
        if (not isinstance(trust,dict) or set(trust)!=set(scope.project_profiles)
                or any(not isinstance(labels,list) or len(labels)>32 or labels!=sorted(set(labels))
                       or any(not isinstance(label,str) or len(label)>160 for label in labels) for labels in trust.values())
                or (any(trust.values()) and not scope.acknowledge_project_trust)):
            raise ValueError('invalid project trust snapshot')
        at = now or datetime.now(timezone.utc)
        created = datetime.fromisoformat(value['created_at'])
        expires = datetime.fromisoformat(value['expires_at']) if value['expires_at'] is not None else None
        expiry_valid = (expires is None if scope.valid_for_days is None else (
            expires is not None and expires.tzinfo is not None and expires > at
            and expires-created == timedelta(days=scope.valid_for_days)))
        historical_fields = {'admission_policy'} if 'admission_policy' not in value['scope'] else set()
        if (scope.model_dump(mode='json', exclude=historical_fields) != value['scope']
                or created.tzinfo is None or created > at or not expiry_valid
                or value['enrollment_id'] != record.enrollment_id
                or value['machine_id'] != record.invited_machine_id
                or value['owner_user_id'] != record.owner_user_id or value['issued_by'] != record.issued_by
                or release_for_runtime(value['runtime_version']).runtime_version != value['runtime_version']
                or value['offer_sha256'] != canonical_digest({k:v for k,v in value.items() if k!='offer_sha256'})):
            raise ValueError('invalid offer binding')
        return value
    except (ValueError, TypeError, KeyError, OverflowError):
        raise EnrollmentUnavailable() from None
