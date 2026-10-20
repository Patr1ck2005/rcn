"""Explicit owner/admin consent for per-Attempt full-machine CPU scheduling."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from .auth import AuthContext, require_role
from .hashing import sha256_value
from .models import FullCpuOverride, UserRole


class FullCpuModeRequest(BaseModel):
    enabled: bool = Field(strict=True)
    reason: str = Field(min_length=1, max_length=1000)
    owner_consent_reference: str = Field(min_length=1, max_length=500)
    expected_policy_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    max_threads_per_attempt: int | None = Field(default=None, ge=1, strict=True)

    @field_validator('reason', 'owner_consent_reference')
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError('explicit owner consent and reason must not be blank')
        return value.strip()


def build_machine_cpu_override_router(*, repository, service, auth):
    router = APIRouter()

    @router.put('/v1/admin/machines/{machine_id}/cpu-mode')
    def set_full_cpu_mode(machine_id: str, body: FullCpuModeRequest,
                          context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        machine = repository.get_machine(machine_id)
        policy = repository.get_policy(machine_id)
        if machine is None or policy is None:
            raise HTTPException(status_code=404, detail='machine policy not found')
        # This mode consumes the complete host budget and must be the owner's
        # explicit decision; administrator access alone is not owner consent.
        if context.actor_id != machine.owner_user_id:
            raise HTTPException(status_code=403, detail='full CPU mode requires the machine owner administrator')
        if policy.member_execution_limit is not None:
            raise HTTPException(status_code=409, detail='member invitation CPU limits cannot use this override')
        if not body.enabled and 'max_threads_per_attempt' in body.model_fields_set:
            raise HTTPException(status_code=422, detail='disabled CPU override cannot specify an Attempt thread cap')
        before = policy.model_dump(mode='json')
        if sha256_value(before) != body.expected_policy_sha256:
            raise HTTPException(status_code=409, detail='machine policy changed; read the same machine again')
        changes = {'full_cpu_override': None}
        if body.enabled:
            # Old clients cannot silently remove a newer bounded CPU mode.
            # Explicit null is an audited owner request to restore all threads.
            thread_cap = (body.max_threads_per_attempt
                          if 'max_threads_per_attempt' in body.model_fields_set
                          else (policy.full_cpu_override.max_threads_per_attempt
                                if policy.full_cpu_override is not None else None))
            changes.update(max_cpus=machine.total_cpus, full_cpu_override=FullCpuOverride(
                authorized_by=context.actor_id,
                reason=body.reason + '; owner consent: ' + body.owner_consent_reference,
                authorized_at=datetime.now(timezone.utc),
                max_threads_per_attempt=thread_cap,
            ))
        updated = policy.model_copy(update=changes)
        cpu_limit = updated.effective_cpu_cap(machine.total_cpus)
        if (updated.full_cpu_override is not None
                and updated.full_cpu_override.max_threads_per_attempt is not None
                and updated.full_cpu_override.max_threads_per_attempt > cpu_limit):
            raise HTTPException(status_code=409, detail='Attempt thread cap exceeds the effective hardware/policy CPU budget')
        try:
            service._event('machine.full_cpu_override_requested', context.actor_id, 'machine', machine_id,
                enabled=body.enabled, reason=body.reason,
                max_threads_per_attempt=(updated.full_cpu_override.max_threads_per_attempt
                                         if updated.full_cpu_override else None),
                owner_consent_reference=body.owner_consent_reference,
                expected_policy_sha256=body.expected_policy_sha256)
            updated = service.update_policy(updated, actor_id=context.actor_id,
                                             full_cpu_override_authorized=True,
                                             expected_policy_sha256=body.expected_policy_sha256)
            service._event('machine.full_cpu_override_changed', context.actor_id, 'machine', machine_id,
                enabled=body.enabled, reason=body.reason,
                owner_consent_reference=body.owner_consent_reference,
                before=before, after=updated.model_dump(mode='json'),
                existing_attempt_resources_preserved=True)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {'machine_id':machine_id, 'enabled':body.enabled,
                'policy':updated.model_dump(mode='json'),
                'effective_cpu_cap':updated.effective_cpu_cap(machine.total_cpus),
                'effective_max_threads_per_attempt':min(cpu_limit,
                    updated.full_cpu_override.max_threads_per_attempt or cpu_limit)
                    if updated.full_cpu_override else None,
                'new_attempt_cpu_mode':('capped_per_attempt'
                    if updated.full_cpu_override and updated.full_cpu_override.max_threads_per_attempt is not None
                    else 'full_machine_per_attempt' if body.enabled else 'budgeted'),
                'existing_attempt_resources_preserved':True}

    return router
