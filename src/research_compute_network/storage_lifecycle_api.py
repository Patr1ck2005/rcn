"""Authenticated adapter custody and auditable storage-operator endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .auth import AuthContext, require_role
from .models import UserRole
from .storage_lifecycle import LifecycleError, ProjectCustodyPolicy, UnitCustodyReceipt
from .scientific_retention import ModelRetirementPolicy, ScientificCustodyReceipt, ScientificExportAcceptance, ScientificDependencyCompletion
from .origin_retirement import (OriginRetirementSelection, OriginFileAuthorization,
    OriginFileCompletion, OriginPermitRecovery, OriginFileAbort, OriginReaderRequest, OriginReaderRelease)
from .derived_input_retention import DerivedInputRegistration


class UnitSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str
    work_unit_id: str
    producer_attempt_id: str


class RetirementRequest(UnitSelection):
    idempotency_key: str = Field(min_length=1, max_length=192)


class RetirementBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_files: int = Field(default=16, ge=1, le=1024)
    max_units: int = Field(default=4, ge=1, le=64)


class RevokeReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=1, max_length=2000)


class ScientificRetirementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    acceptance_id: str
    idempotency_key: str = Field(min_length=1, max_length=192)


def build_storage_lifecycle_router(*, lifecycle, auth, require_owner):
    router = APIRouter()

    def owned(job_id, unit_id, context):
        job = lifecycle.repository.get_origin_transfer_job(job_id, unit_id)
        if job is None:
            raise HTTPException(404, "job not found")
        require_owner(job, context)

    def checked(operation):
        try:
            return operation()
        except LifecycleError as exc:
            status = 403 if exc.reason_code in {
                "authenticated_adapter_actor_mismatch", "origin_adapter_binding_mismatch"} else 409
            raise HTTPException(status, {"reason_code": exc.reason_code}) from exc
        except (OSError, ValueError) as exc:
            # Do not expose local paths or arbitrary adapter error messages.
            raise HTTPException(409, {"reason_code": getattr(exc, "reason_code", "storage_unavailable_or_invalid")}) from exc

    @router.put("/v1/admin/storage/projects/{project_id}/policy")
    def register_policy(project_id: str, policy: ProjectCustodyPolicy,
                        context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        if project_id != policy.project_id:
            raise HTTPException(400, "policy project does not match the route")
        return checked(lambda: lifecycle.register_policy(policy, actor_id=context.actor_id))

    @router.get("/v1/admin/storage/projects/{project_id}/policy")
    def get_policy(project_id: str, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return lifecycle.get_policy(project_id)

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/custody")
    def custody(job_id: str, unit_id: str, receipt: UnitCustodyReceipt,
                context: AuthContext = Depends(auth.actor)):
        owned(job_id, unit_id, context)
        if (receipt.job_id, receipt.work_unit_id) != (job_id, unit_id):
            raise HTTPException(400, "custody Unit does not match the route")
        return checked(lambda: lifecycle.record_receipt(receipt, actor_id=context.actor_id))

    @router.get("/v1/jobs/{job_id}/units/{unit_id}/custody/{attempt_id}")
    def custody_state(job_id: str, unit_id: str, attempt_id: str,
                      context: AuthContext = Depends(auth.actor)):
        owned(job_id, unit_id, context)
        return checked(lambda: lifecycle.state(job_id, unit_id, attempt_id))

    @router.post("/v1/admin/storage/custody/{receipt_id}/revoke")
    def revoke(receipt_id: str, request: RevokeReceiptRequest,
               context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        checked(lambda: lifecycle.revoke_receipt(receipt_id, actor_id=context.actor_id, reason=request.reason))
        return {"receipt_id": receipt_id, "revoked": True}

    @router.post("/v1/admin/storage/retirements/preview")
    def preview(request: UnitSelection, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return lifecycle.preview_retirement(request.job_id, request.work_unit_id, request.producer_attempt_id)

    @router.post("/v1/admin/storage/retirements")
    def retire(request: RetirementRequest, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return checked(lambda: lifecycle.create_retirement(request.job_id, request.work_unit_id,
            request.producer_attempt_id, idempotency_key=request.idempotency_key, actor_id=context.actor_id))

    @router.get("/v1/admin/storage/retirements/{intent_id}")
    def intent(intent_id: str, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return checked(lambda: lifecycle.get_intent(intent_id))

    @router.post("/v1/admin/storage/retirements/{intent_id}/run")
    def run(intent_id: str, batch: RetirementBatch,
            context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return checked(lambda: lifecycle.run_retirement(intent_id, max_files=batch.max_files,
                                                        actor_id=context.actor_id))

    @router.post("/v1/admin/storage/gc")
    def gc(batch: RetirementBatch, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return checked(lambda: lifecycle.run_gc_batch(max_units=batch.max_units, max_files=batch.max_files))

    @router.get("/v1/admin/storage/projects/{project_id}/model-policy")
    @router.get("/v1/projects/{project_id}/model-policy")
    def read_model_policy(project_id: str, context: AuthContext = Depends(auth.actor)):
        grant = lifecycle.repository.get_project_grant(project_id)
        if grant is None:
            raise HTTPException(404, "project not registered")
        if not context.has_role(UserRole.ADMIN) and context.actor_id != grant.owner_user_id:
            raise HTTPException(403, "project owner or administrator required")
        return checked(lambda: lifecycle.scientific.get_policy(project_id))

    @router.put("/v1/admin/storage/projects/{project_id}/model-policy")
    def model_policy(project_id: str, policy: ModelRetirementPolicy,
                     context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        if project_id != policy.project_id:
            raise HTTPException(400, "policy project does not match the route")
        return checked(lambda: lifecycle.scientific.register_policy(policy, actor_id=context.actor_id))

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/scientific-exports")
    def scientific_exports(job_id: str, unit_id: str, proof: ScientificExportAcceptance,
                           context: AuthContext = Depends(auth.actor)):
        owned(job_id, unit_id, context)
        if (proof.job_id, proof.work_unit_id) != (job_id, unit_id):
            raise HTTPException(400, "scientific export Unit does not match the route")
        return checked(lambda: lifecycle.scientific.record_acceptance(proof, actor_id=context.actor_id))

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/scientific-custody")
    def scientific_custody(job_id: str, unit_id: str, receipt: ScientificCustodyReceipt,
                           context: AuthContext = Depends(auth.actor)):
        owned(job_id, unit_id, context)
        proof = checked(lambda: lifecycle.scientific.get_acceptance(receipt.acceptance_id))
        if (proof.job_id, proof.work_unit_id) != (job_id, unit_id):
            raise HTTPException(400, "scientific custody Unit does not match the route")
        return checked(lambda: lifecycle.scientific.record_custody(receipt, actor_id=context.actor_id))

    @router.get("/v1/jobs/{job_id}/units/{unit_id}/scientific-retention/{attempt_id}")
    def scientific_state(job_id: str, unit_id: str, attempt_id: str,
                         context: AuthContext = Depends(auth.actor)):
        owned(job_id, unit_id, context)
        checked(lambda: lifecycle._binding(job_id, unit_id, attempt_id, require_custody=False))
        return checked(lambda: lifecycle.scientific.state(job_id, unit_id, attempt_id))

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/scientific-dependencies")
    def scientific_dependency(job_id: str, unit_id: str, receipt: ScientificDependencyCompletion,
                              context: AuthContext = Depends(auth.actor)):
        owned(job_id, unit_id, context)
        proof = checked(lambda: lifecycle.scientific.get_acceptance(receipt.acceptance_id))
        if (proof.job_id, proof.work_unit_id) != (job_id, unit_id):
            raise HTTPException(400, "scientific dependency Unit does not match the route")
        return checked(lambda: lifecycle.scientific.record_dependency(receipt, actor_id=context.actor_id))

    @router.post("/v1/admin/storage/scientific-evidence/{record_id}/revoke")
    def revoke_scientific(record_id: str, request: RevokeReceiptRequest,
                          context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        checked(lambda: lifecycle.scientific.revoke(record_id, actor_id=context.actor_id, reason=request.reason))
        return {"record_id": record_id, "revoked": True}

    @router.get("/v1/admin/storage/model-retirements/preview/{acceptance_id}")
    def model_preview(acceptance_id: str, context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return lifecycle.scientific.preview(acceptance_id)

    @router.post("/v1/admin/storage/model-retirements")
    def model_retire(request: ScientificRetirementRequest,
                     context: AuthContext = Depends(auth.actor)):
        require_role(context, UserRole.ADMIN)
        return checked(lambda: lifecycle.scientific.create_retirement(request.acceptance_id,
            idempotency_key=request.idempotency_key, actor_id=context.actor_id))

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/derived-inputs")
    def derived_input(job_id: str, unit_id: str, request: DerivedInputRegistration,
                      context: AuthContext = Depends(auth.actor)):
        owned(job_id, unit_id, context)
        if (request.job_id, request.work_unit_id) != (job_id, unit_id):
            raise HTTPException(400, "derived input Unit does not match the route")
        return checked(lambda: lifecycle.derived_inputs.register(request, actor_id=context.actor_id))

    @router.get("/v1/jobs/{job_id}/units/{unit_id}/derived-inputs/{attempt_id}")
    def derived_input_state(job_id: str, unit_id: str, attempt_id: str,
                            context: AuthContext = Depends(auth.actor)):
        owned(job_id, unit_id, context)
        return checked(lambda: lifecycle.derived_inputs.state(job_id, unit_id, attempt_id, actor_id=context.actor_id))

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/derived-inputs/{record_id}/revoke")
    def revoke_derived_input(job_id: str, unit_id: str, record_id: str, request: RevokeReceiptRequest,
                             context: AuthContext = Depends(auth.actor)):
        owned(job_id, unit_id, context)
        with lifecycle._connect() as db:
            registration = checked(lambda: lifecycle.derived_inputs.get(db, record_id))
        if (registration.job_id, registration.work_unit_id) != (job_id, unit_id):
            raise HTTPException(400, "derived input Unit does not match the route")
        checked(lambda: lifecycle.derived_inputs.revoke(record_id, actor_id=context.actor_id, reason=request.reason))
        return {"record_id": record_id, "revoked": True}

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/origin-retirements")
    def origin_retire(job_id: str, unit_id: str, request: OriginRetirementSelection,
                      context: AuthContext = Depends(auth.actor)):
        owned(job_id, unit_id, context)
        if (request.job_id, request.work_unit_id) != (job_id, unit_id):
            raise HTTPException(400, "origin retirement Unit does not match the route")
        if request.operation_kind == "solved_model_worker":
            raise HTTPException(409, {"reason_code": "machine_agent_coordination_required"})
        return checked(lambda: lifecycle.origin_retirement.create(request, actor_id=context.actor_id))

    def origin_intent(job_id, unit_id, intent_id, context):
        owned(job_id, unit_id, context)
        intent = lifecycle.origin_retirement.get(intent_id, actor_id=context.actor_id)
        candidate = intent["candidate"]
        if candidate.get("operation_kind") == "solved_model_worker":
            raise LifecycleError("machine_agent_coordination_required")
        if (candidate["job_id"], candidate["work_unit_id"]) != (job_id, unit_id):
            raise LifecycleError("origin_retirement_route_mismatch")
        return intent

    @router.get("/v1/jobs/{job_id}/units/{unit_id}/origin-retirements/{intent_id}")
    def get_origin_retirement(job_id: str, unit_id: str, intent_id: str,
                              context: AuthContext = Depends(auth.actor)):
        return checked(lambda: origin_intent(job_id, unit_id, intent_id, context))

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/origin-retirements/{intent_id}/authorize")
    def authorize_origin_file(job_id: str, unit_id: str, intent_id: str, request: OriginFileAuthorization,
                              context: AuthContext = Depends(auth.actor)):
        checked(lambda: origin_intent(job_id, unit_id, intent_id, context))
        return checked(lambda: lifecycle.origin_retirement.authorize(intent_id, request, actor_id=context.actor_id))

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/origin-retirements/{intent_id}/complete")
    def complete_origin_file(job_id: str, unit_id: str, intent_id: str, request: OriginFileCompletion,
                             context: AuthContext = Depends(auth.actor)):
        checked(lambda: origin_intent(job_id, unit_id, intent_id, context))
        return checked(lambda: lifecycle.origin_retirement.complete(intent_id, request, actor_id=context.actor_id))

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/origin-retirements/{intent_id}/reconcile")
    def reconcile_origin_file(job_id: str, unit_id: str, intent_id: str, request: OriginPermitRecovery,
                              context: AuthContext = Depends(auth.actor)):
        checked(lambda: origin_intent(job_id, unit_id, intent_id, context))
        return checked(lambda: lifecycle.origin_retirement.reconcile(intent_id, request, actor_id=context.actor_id))

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/origin-retirements/{intent_id}/abort")
    def abort_origin_file(job_id: str, unit_id: str, intent_id: str, request: OriginFileAbort,
                          context: AuthContext = Depends(auth.actor)):
        checked(lambda: origin_intent(job_id, unit_id, intent_id, context))
        return checked(lambda: lifecycle.origin_retirement.abort(intent_id, request, actor_id=context.actor_id))

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/origin-readers")
    def pin_origin_reader(job_id: str, unit_id: str, request: OriginReaderRequest,
                          context: AuthContext = Depends(auth.actor)):
        owned(job_id, unit_id, context)
        return checked(lambda: lifecycle.origin_retirement.pin_reader(job_id, unit_id, request, actor_id=context.actor_id))

    @router.post("/v1/jobs/{job_id}/units/{unit_id}/origin-readers/{pin_id}/release")
    def release_origin_reader(job_id: str, unit_id: str, pin_id: str, request: OriginReaderRelease,
                              context: AuthContext = Depends(auth.actor)):
        owned(job_id, unit_id, context)
        return checked(lambda: lifecycle.origin_retirement.release_reader(job_id, unit_id, pin_id, request, actor_id=context.actor_id))

    return router
