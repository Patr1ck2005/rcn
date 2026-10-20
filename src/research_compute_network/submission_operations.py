"""Durable, member-bound preview/confirm identity for portable submissions."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .hashing import sha256_value
from .models import PartitionPlan, ProjectStatus
from .partitioning import confirm_partition_plan, job_from_confirmed_plan
from .submission_packages import SubmissionPackageManifest


class SubmissionOperationConflict(ValueError):
    reason_code = "submission_operation_conflict"


class SubmissionOperationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    package_manifest: SubmissionPackageManifest
    requested_unit_count: int | None = Field(default=None, ge=1)
    estimated_seconds_per_item: float | None = Field(default=None, gt=0)
    target_unit_s: int | None = Field(default=None, ge=1, le=86400)
    preferred_max_unit_s: int | None = Field(default=None, ge=1, le=86400)


class SubmissionOperation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    operation_id: str
    actor_id: str
    project_id: str
    payload_sha256: str
    package_contents_sha256: str
    source_request_hash: str
    plan: PartitionPlan
    job_id: str | None = None
    job_request_hash: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    confirmed_at: datetime | None = None


def operation_id(value: str) -> str:
    try:
        result = UUID(value)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("submission operation ID must be a UUID") from exc
    return str(result)


def _authorize(service, actor_id: str, request, *, is_admin=False):
    if request.user_id != actor_id:
        raise PermissionError("submission package belongs to another member")
    from .personal_runtime import authorize_request
    grant = authorize_request(service, request)
    if grant is None or grant.status != ProjectStatus.ACTIVE:
        raise PermissionError("submission project is not active")
    if not is_admin and not grant.authorizes(actor_id):
        raise PermissionError("member is not authorized for this project")
    if request.execution_profile_id not in grant.allowed_profiles:
        raise PermissionError("submission Profile is not authorized for this project")


def put_submission_operation(service, operation_uuid: str, payload: SubmissionOperationRequest,
                             *, actor_id: str, is_admin=False) -> SubmissionOperation:
    op_id = operation_id(operation_uuid)
    payload = SubmissionOperationRequest.model_validate(payload)
    request_sha = sha256_value(payload.model_dump(mode="json"))

    def write(repository):
        from .service import NetworkService
        scoped = NetworkService(repository, runtime_policy=service.runtime_policy)
        if payload.package_manifest.request.user_id != actor_id:
            raise PermissionError("submission package belongs to another member")
        existing = repository.get_submission_operation(op_id)
        if existing is not None:
            if existing.actor_id != actor_id:
                raise PermissionError("submission operation belongs to another member")
            if existing.payload_sha256 != request_sha:
                raise SubmissionOperationConflict("the operation UUID already binds a different request; recover the original operation or explicitly create a new UUID")
            return existing
        # Recovering an immutable original receipt does not authorize another
        # execution. Only planning a new operation requires today's grant.
        _authorize(scoped, actor_id, payload.package_manifest.request, is_admin=is_admin)
        request = payload.package_manifest.request.model_copy(deep=True)
        for name in ("requested_unit_count", "estimated_seconds_per_item", "target_unit_s", "preferred_max_unit_s"):
            value = getattr(payload, name)
            if value is not None:
                setattr(request, name, value)
        # An explicit new operation means a new execution, even when its science
        # matches a terminal or still-active request. Retries retain this UUID.
        request.request_hash = sha256_value({"submission_operation_schema": 1, "operation_id": op_id,
            "actor_id": actor_id, "project_id": request.project_id, "source_request_hash": payload.package_manifest.source_request_hash,
            "package_contents_sha256": payload.package_manifest.package_contents_sha256, "payload_sha256": request_sha})
        # Re-run model cross-field validation after operational option overrides.
        request = type(request).model_validate(request.model_dump(mode="json"))
        plan = scoped.plan_partition(request, actor_id=actor_id)
        result = SubmissionOperation(operation_id=op_id, actor_id=actor_id, project_id=request.project_id,
            payload_sha256=request_sha, package_contents_sha256=payload.package_manifest.package_contents_sha256,
            source_request_hash=payload.package_manifest.source_request_hash, plan=plan)
        repository.put_submission_operation(result)
        scoped._event("submission_operation.planned", actor_id, "submission_operation", op_id,
            project_id=request.project_id, source_request_hash=result.source_request_hash,
            package_contents_sha256=result.package_contents_sha256, plan_id=plan.plan_id)
        return result
    return service.repository.submission_transaction(write)


def confirm_submission_operation(service, operation_uuid: str, *, actor_id: str, is_admin=False) -> SubmissionOperation:
    op_id = operation_id(operation_uuid)

    def write(repository):
        from .service import NetworkService
        scoped = NetworkService(repository, runtime_policy=service.runtime_policy)
        result = repository.get_submission_operation(op_id)
        if result is None:
            raise KeyError("submission operation not found")
        if result.actor_id != actor_id:
            raise PermissionError("submission operation belongs to another member")
        if result.plan.request.user_id != actor_id:
            raise PermissionError("submission package belongs to another member")
        if result.job_id is not None:
            if repository.get_job(result.job_id) is None:
                raise SubmissionOperationConflict("the durable Job receipt is missing; operator reconciliation is required")
            return result
        _authorize(scoped, actor_id, result.plan.request, is_admin=is_admin)
        # Validate current grant/runtime compatibility, without changing science
        # or inventing an unrelated execution after a lost response.
        job = scoped.confirm_partition(result.plan.plan_id, actor_id=actor_id)
        result.plan = repository.get_partition_plan(result.plan.plan_id)
        result.plan.confirmed_job_id = job.job_id
        result.job_id = job.job_id
        result.job_request_hash = job.request_hash
        result.confirmed_at = datetime.now(timezone.utc)
        repository.put_partition_plan(result.plan)
        repository.put_submission_operation(result)
        scoped._event("submission_operation.confirmed", actor_id, "submission_operation", op_id,
            project_id=result.project_id, job_id=result.job_id, source_request_hash=result.source_request_hash,
            package_contents_sha256=result.package_contents_sha256)
        return result
    return service.repository.submission_transaction(write)
