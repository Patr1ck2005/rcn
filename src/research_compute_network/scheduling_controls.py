"""Actor-bound preview/confirm of operational scheduling, no machine writes."""
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer
from sqlalchemy import select, text, update

from .dispatch_policy import SchedulingPolicy
from .hashing import sha256_value
from .models import AuditEvent, FeatureSettings
from .repository import EventRow, EventSequenceRow, FeatureSettingsRow


class SchedulingChange(BaseModel):
    model_config=ConfigDict(extra='forbid')
    expected_revision: int=Field(ge=0,strict=True)
    policy: SchedulingPolicy
    reason: str=Field(min_length=1,max_length=1000)

    @model_serializer(mode='wrap')
    def preserve_explicit_priority_fields(self, handler):
        payload = handler(self)
        for name in ('default_priority', 'project_priorities', 'short_compute_priority', 'small_batch_max_parallel_seconds'):
            if name in self.policy.model_fields_set:
                payload['policy'][name] = getattr(self.policy, name)
        return payload

    @field_validator('reason')
    @classmethod
    def clean_reason(cls,value):
        if not value.strip() or any(ord(c)<32 for c in value):raise ValueError('explicit single-line reason required')
        return value.strip()


class SchedulingConfirmation(SchedulingChange):
    confirmation_hash: str=Field(pattern=r'^[0-9a-f]{64}$')


def describe(settings):
    policy=settings.scheduling_policy or SchedulingPolicy()
    return {'policy':policy.model_dump(mode='json'),'revision':settings.scheduling_revision,
            'strategies':['balanced','small_batch_first','throughput'],
            'parallel_small_batch_schema':1,
            'running_attempts_unchanged':True,'scientific_inputs_changed':False,
            'fairness_basis':'window-overlapped requested-resource time; not contribution quotas',
            'defaults_only':settings.scheduling_policy is None}


def merged_policy(candidate, current):
    """Old clients omit these fields; only explicit input may replace them."""
    values = candidate.model_dump(mode='json')
    current = current or SchedulingPolicy()
    for name in ('default_priority', 'project_priorities', 'short_compute_priority', 'small_batch_max_parallel_seconds'):
        values[name] = getattr(candidate if name in candidate.model_fields_set else current, name)
    return SchedulingPolicy.model_validate(values)


def confirmation_hash(change,actor_id,*,policy=None):
    payload = change.model_dump(mode='json',exclude={'confirmation_hash'})
    if policy is not None:
        payload['policy'] = policy.model_dump(mode='json')
    return sha256_value({'kind':'scheduling-policy-v1','actor_id':actor_id,
                        **payload})


def preview(repository,change,actor_id):
    current=repository.get_feature_settings()
    if current.scheduling_revision!=change.expected_revision:raise ValueError('scheduling_revision_conflict')
    candidate=merged_policy(change.policy,current.scheduling_policy)
    candidate_payload=candidate.model_dump(mode='json')
    for name in ('default_priority', 'project_priorities', 'short_compute_priority', 'small_batch_max_parallel_seconds'):
        if name in change.policy.model_fields_set:
            candidate_payload[name]=getattr(candidate,name)
    return {'current':describe(current),'candidate':candidate_payload,
            'confirmation_hash':confirmation_hash(change,actor_id,policy=candidate),
            'impact':{'new_assignments_only':True,'existing_attempts_unchanged':True,
                      'owner_caps_unchanged':True,'project_grants_unchanged':True,
                      'priority_defaults_new_submissions_only':True,
                      'accepted_base_priorities_unchanged':True,
                      'no_scientific_preemption':True}}


def confirm(repository,change,actor_id):
    def write():
        with repository._session() as session,session.begin():
            if repository.engine.dialect.name=='sqlite' and repository._transaction_session() is None:
                session.execute(text('BEGIN IMMEDIATE'))
            row=session.scalar(select(FeatureSettingsRow).where(FeatureSettingsRow.settings_id=='global').with_for_update())
            current=FeatureSettings.model_validate(row.payload) if row is not None else FeatureSettings()
            if (current.scheduling_revision != change.expected_revision
                    and not (current.scheduling_revision == change.expected_revision+1
                             and current.scheduling_confirmation == change.confirmation_hash)):
                raise ValueError('scheduling_revision_conflict')
            candidate=merged_policy(change.policy,current.scheduling_policy)
            expected=confirmation_hash(change,actor_id,policy=candidate)
            if change.confirmation_hash!=expected:raise ValueError('scheduling_confirmation_mismatch')
            if current.scheduling_revision==change.expected_revision+1 and current.scheduling_confirmation==expected:
                return {**describe(current),'replayed':True}
            if current.scheduling_revision!=change.expected_revision:raise ValueError('scheduling_revision_conflict')
            before=describe(current)
            current.scheduling_policy=candidate
            current.scheduling_revision+=1
            current.scheduling_confirmation=expected
            current.updated_at=datetime.now(timezone.utc)
            row=row or FeatureSettingsRow(settings_id='global')
            row.payload=current.model_dump(mode='json');session.add(row)
            event=AuditEvent(event_type='scheduling.policy_changed',actor_id=actor_id,
                subject_type='scheduling_policy',subject_id='global',details={
                    'before':before['policy'],'after':candidate.model_dump(mode='json'),
                    'reason':change.reason,'revision':current.scheduling_revision,
                    'confirmation_hash':expected,'running_attempts_unchanged':True})
            event.sequence=session.execute(update(EventSequenceRow).where(EventSequenceRow.sequence_id=='global')
                .values(next_sequence=EventSequenceRow.next_sequence+1).returning(EventSequenceRow.next_sequence)).scalar_one()-1
            session.add(EventRow(event_id=event.event_id,event_type=event.event_type,
                subject_type=event.subject_type,subject_id=event.subject_id,created_at=event.created_at,
                sequence=event.sequence,payload=event.model_dump(mode='json')))
            return {**describe(current),'replayed':False}
    return repository._retry_sqlite_write(write)
