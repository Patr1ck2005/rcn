"""Machine-scoped coordination of hashed, origin-accepted recovery models."""
from __future__ import annotations
import json

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .origin_retirement import (OriginRetirementSelection, OriginFileAuthorization,
    OriginFileCompletion, OriginPermitRecovery, OriginFileAbort)
from .storage_lifecycle import LifecycleError, inventory_payload


class WorkerRetirementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    acceptance_id: str
    idempotency_key: str = Field(min_length=1, max_length=192)


def build_worker_model_retirement_router(*, lifecycle, auth):
    router = APIRouter()
    origin = lifecycle.origin_retirement

    def enabled(machine_id, authorization):
        auth.machine_agent(machine_id, authorization)
        config = lifecycle.repository.get_machine_execution_config(machine_id)
        if config is None or not config.root_uuid or not config.scientific_model_retirement_enabled:
            raise LifecycleError("worker_model_retirement_disabled")
        return config

    def bound(machine_id, acceptance_id):
        proof = lifecycle.scientific.get_acceptance(acceptance_id)
        job, manifest, attempt = lifecycle._binding(proof.job_id, proof.work_unit_id, proof.producer_attempt_id)
        if attempt.machine_id != machine_id or proof.temporary_model_storage != "worker_recovery":
            raise LifecycleError("worker_attempt_binding_mismatch")
        run = lifecycle.repository.get_remote_run(attempt.external_run_id)
        if (run is None or (run.machine_id, run.job_id, run.work_unit_id) !=
                (machine_id, job.job_id, proof.work_unit_id)):
            raise LifecycleError("worker_request_binding_missing")
        return proof, job, manifest, attempt, run

    def checked(operation):
        try:
            return operation()
        except LifecycleError as exc:
            raise HTTPException(409, {"reason_code": exc.reason_code}) from exc
        except (OSError, ValueError) as exc:
            raise HTTPException(409, {"reason_code": "worker_retirement_evidence_invalid"}) from exc

    @router.get("/v1/machines/{machine_id}/model-retirements")
    def candidates(machine_id: str, authorization: str | None = Header(default=None)):
        auth.machine_agent(machine_id, authorization)
        config = lifecycle.repository.get_machine_execution_config(machine_id)
        if config is None or not config.root_uuid or not config.scientific_model_retirement_enabled:
            return {"candidates": [], "reason_code": "worker_model_retirement_disabled"}
        with lifecycle._connect() as db:
            pending = db.execute("SELECT i.intent_id,i.payload FROM storage_lifecycle_intents i "
                "LEFT JOIN scientific_retention_checks c ON c.acceptance_id=json_extract(i.payload,'$.acceptance_id') "
                "WHERE i.state='pending' AND i.operation_kind LIKE 'solved_model_worker:%' "
                "AND json_extract(i.payload,'$.target.host_id')=? "
                "ORDER BY COALESCE(c.checked_at,''),i.created_at LIMIT 4", (machine_id,)).fetchall()
            rows = db.execute("SELECT a.acceptance_id FROM scientific_export_acceptances a "
                "LEFT JOIN scientific_retention_checks c ON c.acceptance_id=a.acceptance_id "
                "WHERE a.revoked_at IS NULL AND json_extract(a.payload,'$.temporary_model_storage')='worker_recovery' "
                "AND json_extract(a.payload,'$.producer_external_id') IN "
                "(SELECT external_run_id FROM remote_runs WHERE machine_id=?) "
                "ORDER BY COALESCE(c.checked_at,''),a.recorded_at LIMIT 4", (machine_id,)).fetchall()
        result, blocked = [], []
        pending_ids = set()
        for row in pending:
            payload = json.loads(row['payload'])
            try:
                # An uncertain syscall must remain reportable even if its
                # scientific acceptance was revoked after authorization.
                job, _, attempt = lifecycle._binding(payload['job_id'], payload['work_unit_id'], payload['producer_attempt_id'])
                if attempt.machine_id != machine_id:
                    raise LifecycleError('worker_attempt_binding_mismatch')
                result.append({**payload, 'intent_id': row['intent_id'], 'recovery_only': True,
                               'project_id': job.project_id})
                pending_ids.add(payload['acceptance_id'])
                with lifecycle._transaction() as db:
                    from .storage_lifecycle import _now
                    db.execute("INSERT INTO scientific_retention_checks VALUES(?,?) ON CONFLICT(acceptance_id) "
                               "DO UPDATE SET checked_at=excluded.checked_at", (payload['acceptance_id'], _now()))
            except (OSError, ValueError) as exc:
                blocked.append({'intent_id': row['intent_id'], 'reason_code': getattr(exc, 'reason_code', 'worker_retirement_evidence_invalid')})
        for row in rows:
            key = row[0]
            if len(result) >= 4:
                break
            if key in pending_ids:
                continue
            try:
                proof, job, manifest, attempt, run = bound(machine_id, key)
                with lifecycle._transaction() as db:
                    from .storage_lifecycle import _now
                    db.execute("INSERT INTO scientific_retention_checks VALUES(?,?) ON CONFLICT(acceptance_id) "
                               "DO UPDATE SET checked_at=excluded.checked_at", (key, _now()))
                    _, _, _, _, _, _, expires, files = lifecycle.scientific._evidence(db, key)
                result.append({"acceptance_id": key, "project_id": proof.project_id,
                    "job_id": proof.job_id, "work_unit_id": proof.work_unit_id,
                    "producer_attempt_id": proof.producer_attempt_id, "producer_external_id": proof.producer_external_id,
                    "request_hash": run.request_hash, "job_request_hash": job.request_hash,
                    "files": inventory_payload(files), "temporary_inventory_file": proof.temporary_inventory_file.model_dump(mode="json"),
                    "original_files": inventory_payload(manifest.files), "manifest_sha256": proof.manifest_sha256,
                    "root_uuid": config.root_uuid, "expires_at": expires.isoformat(),
                    "directory_relative_path": "/".join(("runs", "retained", "success", job.project_id, job.job_id, proof.work_unit_id))})
            except (OSError, ValueError) as exc:
                blocked.append({"acceptance_id": key, "reason_code": getattr(exc, "reason_code", "worker_retirement_evidence_invalid")})
        return {"candidates": result, "blocked": blocked}

    @router.post("/v1/machines/{machine_id}/model-retirements")
    def create(machine_id: str, request: WorkerRetirementRequest, authorization: str | None = Header(default=None)):
        def execute():
            enabled(machine_id, authorization)
            proof, job, _, _, _ = bound(machine_id, request.acceptance_id)
            selection = OriginRetirementSelection(operation_kind="solved_model_worker", idempotency_key=request.idempotency_key,
                job_id=proof.job_id, work_unit_id=proof.work_unit_id, producer_attempt_id=proof.producer_attempt_id,
                target=origin.worker_location(machine_id),
                directory_relative_path="/".join(("runs", "retained", "success", job.project_id, job.job_id, proof.work_unit_id)),
                acceptance_id=request.acceptance_id)
            response = origin.create(selection, actor_id=job.user_id)
            with lifecycle._transaction() as db:
                lifecycle._audit(db, "storage.worker_origin_delegated", "machine-agent:" + machine_id,
                                 response["intent_id"], action="create", delegated_origin=job.user_id)
            return response
        return checked(execute)

    def owned(machine_id, intent_id, authorization):
        auth.machine_agent(machine_id, authorization)
        intent = lifecycle.get_intent(intent_id)
        payload = intent["candidate"]
        if payload.get("operation_kind") != "solved_model_worker":
            raise LifecycleError("worker_intent_required")
        job, _, attempt = lifecycle._binding(payload["job_id"], payload["work_unit_id"], payload["producer_attempt_id"])
        if attempt.machine_id != machine_id or payload["target"]["host_id"] != machine_id:
            raise LifecycleError("worker_attempt_binding_mismatch")
        # Explicit delegated ownership never changes the original Job actor.
        origin.get(intent_id, actor_id=job.user_id)
        return job

    @router.get("/v1/machines/{machine_id}/model-retirements/{intent_id}")
    def get(machine_id: str, intent_id: str, authorization: str | None = Header(default=None)):
        return checked(lambda: origin.get(intent_id, actor_id=owned(machine_id, intent_id, authorization).user_id))

    def action(machine_id, intent_id, authorization, name, request):
        def execute():
            job = owned(machine_id, intent_id, authorization)
            if name == "authorize":
                enabled(machine_id, authorization)
            result = getattr(origin, name)(intent_id, request, actor_id=job.user_id)
            with lifecycle._transaction() as db:
                lifecycle._audit(db, "storage.worker_origin_delegated", "machine-agent:" + machine_id,
                                 intent_id, action=name, delegated_origin=job.user_id)
            return result
        return checked(execute)

    @router.post("/v1/machines/{machine_id}/model-retirements/{intent_id}/authorize")
    def authorize(machine_id: str, intent_id: str, request: OriginFileAuthorization, authorization: str | None = Header(default=None)):
        return action(machine_id, intent_id, authorization, "authorize", request)

    @router.post("/v1/machines/{machine_id}/model-retirements/{intent_id}/complete")
    def complete(machine_id: str, intent_id: str, request: OriginFileCompletion, authorization: str | None = Header(default=None)):
        return action(machine_id, intent_id, authorization, "complete", request)

    @router.post("/v1/machines/{machine_id}/model-retirements/{intent_id}/reconcile")
    def reconcile(machine_id: str, intent_id: str, request: OriginPermitRecovery, authorization: str | None = Header(default=None)):
        return action(machine_id, intent_id, authorization, "reconcile", request)

    @router.post("/v1/machines/{machine_id}/model-retirements/{intent_id}/abort")
    def abort(machine_id: str, intent_id: str, request: OriginFileAbort, authorization: str | None = Header(default=None)):
        return action(machine_id, intent_id, authorization, "abort", request)

    return router
