"""Personal submission/credit views; all identity comes from existing auth."""
from __future__ import annotations

from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, Field

from .auth import AuthContext, require_role
from .compute_credits import ComputeCredits, CreditError
from .metadata_actions import (MetadataActionConflict, MetadataActionForbidden,
    execute_metadata_action, metadata_action_request)
from .models import UserRole
from .submission_policy import PersonSubmissionPolicy, SubmissionPolicyError, SubmissionPolicyStore


class MeteringUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    metering_enabled: bool = Field(strict=True)


class CreditAdjustment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_id: str = Field(min_length=1, max_length=160)
    cpu_core_hours: float = Field(default=0, ge=0, allow_inf_nan=False)
    gpu_device_hours: float = Field(default=0, ge=0, allow_inf_nan=False)
    reason: str = Field(min_length=1, max_length=1000)


class PoolConsentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    free_idle_enabled: bool = Field(strict=True)
    mutual_enabled: bool = Field(default=True, strict=True)


class MachineWeightUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cpu_weight: Decimal = Field(gt=0, le=1_000_000, max_digits=13, decimal_places=6)
    gpu_weight: Decimal = Field(gt=0, le=1_000_000, max_digits=13, decimal_places=6)


def build_personal_access_router(*, repository, auth, policies=None, credits=None) -> APIRouter:
    policies = policies or SubmissionPolicyStore(repository)
    credits = credits or ComputeCredits(repository)
    router = APIRouter()

    def invoke(operation, *args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except (CreditError, SubmissionPolicyError) as exc:
            status = 403 if exc.reason_code in {"admin_required", "machine_owner_consent_required"} else 409
            raise HTTPException(status_code=status, detail={"reason_code": exc.reason_code}) from exc

    @router.get("/v1/me/submission-policy")
    def my_policy(context: AuthContext = Depends(auth.actor)):
        return policies.effective_policy(context.actor_id)

    @router.get("/v1/me/credits")
    @router.get("/v1/me/compute-credits")
    def my_credits(context: AuthContext = Depends(auth.actor)):
        return {**credits.balance(context.actor_id), "settings": credits.settings(),
                "journal": credits.journal(context.actor_id)}

    @router.get("/v1/admin/people/{person_id}/submission-policy")
    def get_policy(person_id: str, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        if repository.get_user(person_id) is None:
            raise HTTPException(status_code=404, detail="person not found")
        return policies.effective_policy(person_id)

    @router.put("/v1/admin/people/{person_id}/submission-policy")
    def set_policy(person_id: str, body: PersonSubmissionPolicy, context: AuthContext = Depends(auth.actor),
                   action: tuple = Depends(metadata_action_request)):
        require_role(context, UserRole.ADMIN)
        if body.person_id != person_id:
            raise HTTPException(status_code=409, detail={"reason_code": "submission_person_mismatch"})
        try:
            return execute_metadata_action(repository, request_id=action[0], actor_id=context.actor_id,
                kind="personal_submission_policy", subject_id=person_id, payload=action[1],
                mutate=lambda: jsonable_encoder(invoke(policies.set_policy, body, actor_id=context.actor_id)))
        except MetadataActionForbidden as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except MetadataActionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.get("/v1/admin/people/{person_id}/compute-credits")
    def get_credits(person_id: str, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return {**credits.balance(person_id), "journal": credits.journal(person_id)}

    @router.post("/v1/admin/people/{person_id}/compute-credits/adjustments")
    def adjust_credits(person_id: str, body: CreditAdjustment, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return invoke(credits.adjust, person_id, actor_id=context.actor_id, **body.model_dump())

    @router.get("/v1/admin/compute-credits/settings")
    def get_settings(context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return credits.settings()

    @router.put("/v1/admin/compute-credits/settings")
    def set_settings(body: MeteringUpdate, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return invoke(credits.set_metering, body.metering_enabled, actor_id=context.actor_id)

    @router.get("/v1/machines/{machine_id}/compute-pool-consent")
    def get_pool_consent(machine_id: str, context: AuthContext = Depends(auth.actor)):
        machine = repository.get_machine(machine_id)
        if machine is None:
            raise HTTPException(status_code=404, detail="machine not found")
        if machine.owner_user_id != context.actor_id and not context.has_role(UserRole.ADMIN):
            raise HTTPException(status_code=403, detail={"reason_code": "machine_owner_required"})
        return credits.machine_pool_consent(machine_id)

    @router.put("/v1/machines/{machine_id}/compute-pool-consent")
    def set_pool_consent(machine_id: str, body: PoolConsentUpdate, context: AuthContext = Depends(auth.actor)):
        # Admin status cannot substitute for the machine owner's free-pool consent.
        return invoke(credits.set_machine_pool_consent, machine_id, actor_id=context.actor_id, **body.model_dump())

    @router.get("/v1/admin/machines/{machine_id}/compute-credit-weights")
    def get_machine_weights(machine_id: str, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return credits.machine_weights(machine_id)

    @router.put("/v1/admin/machines/{machine_id}/compute-credit-weights")
    def set_machine_weights(machine_id: str, body: MachineWeightUpdate, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return invoke(credits.set_machine_weights, machine_id, actor_id=context.actor_id, **body.model_dump())

    return router
