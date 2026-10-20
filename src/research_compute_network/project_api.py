"""HTTP compatibility routes for the project-access domain."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from .auth import AuthContext, PilotAuthenticator, require_role
from .metadata_actions import (MetadataActionConflict, MetadataActionForbidden,
    execute_metadata_action, metadata_action_request)
from .models import ProjectGrant, ProjectRegistrationRequest, UserRole
from .repository import MetadataRepository
from .service import NetworkService


class ProjectRegistrationCreateRequest(BaseModel):
    project_id: str = Field(
        min_length=1,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    display_name: str = Field(min_length=1, max_length=160)
    purpose: str = Field(min_length=1, max_length=1000)
    requested_profiles: set[str] = Field(default_factory=set)


class ProjectRegistrationReviewRequest(BaseModel):
    approve: bool
    allowed_profiles: set[str] = Field(default_factory=set)
    priority_ceiling: int = Field(default=0, ge=-100, le=100)
    reason: str = Field(default="", max_length=1000)


class ProjectFreezeRequest(BaseModel):
    frozen: bool
    reason: str = Field(default="", max_length=1000)


def build_project_router(
    *,
    repository: MetadataRepository,
    service: NetworkService,
    auth: PilotAuthenticator,
) -> APIRouter:
    router = APIRouter()

    def metadata_mutation(action, context, kind, subject_id, mutate):
        try:
            return execute_metadata_action(repository, request_id=action[0],
                actor_id=context.actor_id, kind=kind, subject_id=subject_id,
                payload=action[1], mutate=lambda: jsonable_encoder(mutate()))
        except MetadataActionForbidden as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except MetadataActionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    def require_project_owner(project_id, context):
        grant = repository.get_project_grant(project_id)
        if grant is None:
            raise HTTPException(status_code=404, detail="project grant not found")
        if context.actor_id != grant.owner_user_id:
            raise HTTPException(status_code=403, detail={"reason_code": "project_owner_required",
                "message": "only the project owner can manage trusted submitters"})

    @router.put("/v1/projects/{project_id}")
    def put_project(
        project_id: str,
        grant: ProjectGrant,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        if project_id != grant.project_id:
            raise HTTPException(status_code=400, detail="project ID mismatch")
        return metadata_mutation(action, context, "project_update", project_id,
            lambda: service.register_project(grant, actor_id=context.actor_id).model_dump(mode="json"))

    @router.get("/v1/projects")
    def projects(context: AuthContext = Depends(auth.actor)) -> list[dict]:
        grants = repository.list_project_grants()
        if UserRole.ADMIN not in context.roles:
            grants = [grant for grant in grants if grant.authorizes(context.actor_id)]
        return [grant.model_dump(mode="json") for grant in grants]

    @router.post("/v1/project-registrations")
    def request_project_registration(
        request_body: ProjectRegistrationCreateRequest,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.MEMBER)
        def mutate():
            request = ProjectRegistrationRequest(
                requested_by=context.actor_id,
                **request_body.model_dump(),
            )
            from .personal_runtime import bootstrap_person, policy_store
            policy = bootstrap_person(service, context.actor_id)
            if policy is not None and policy.approved and policy.auto_project:
                store = policy_store(service)
                for profile_id in request.requested_profiles:
                    store.authorize(context.actor_id, profile_id, request.project_id)
                grant = store.auto_register_project(context.actor_id, request.project_id)
                return {**request.model_dump(mode="json"), "status": "approved", "project": grant.model_dump(mode="json")}
            return service.request_project_registration(
                request,
                actor_id=context.actor_id,
            ).model_dump(mode="json")
        try:
            return metadata_mutation(action, context, "project_registration", request_body.project_id, mutate)
        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "reason_code": "project_registration_conflict",
                    "message": str(exc),
                },
            ) from exc

    @router.get("/v1/project-registrations")
    def project_registrations(
        context: AuthContext = Depends(auth.actor),
    ) -> list[dict]:
        requests = repository.list_project_registrations(
            requested_by=None if UserRole.ADMIN in context.roles else context.actor_id
        )
        return [item.model_dump(mode="json") for item in requests]

    @router.post("/v1/admin/project-registrations/{registration_id}/review")
    def review_project_registration(
        registration_id: str,
        request_body: ProjectRegistrationReviewRequest,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return metadata_mutation(action, context, "project_registration_review", registration_id,
                lambda: service.review_project_registration(
                registration_id,
                approve=request_body.approve,
                allowed_profiles=request_body.allowed_profiles,
                priority_ceiling=request_body.priority_ceiling,
                reason=request_body.reason,
                actor_id=context.actor_id,
            ).model_dump(mode="json"))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "project_review_conflict", "message": str(exc)},
            ) from exc

    @router.put("/v1/projects/{project_id}/trusted-users/{user_id}")
    def add_project_trusted_user(
        project_id: str,
        user_id: str,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_project_owner(project_id, context)
        try:
            return metadata_mutation(action, context, "project_trusted_user_add", project_id,
                lambda: service.update_project_trusted_user(
                project_id,
                user_id,
                add=True,
                actor_id=context.actor_id,
            ).model_dump(mode="json"))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(
                status_code=403,
                detail={"reason_code": "project_owner_required", "message": str(exc)},
            ) from exc

    @router.delete("/v1/projects/{project_id}/trusted-users/{user_id}")
    def remove_project_trusted_user(
        project_id: str,
        user_id: str,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_project_owner(project_id, context)
        try:
            return metadata_mutation(action, context, "project_trusted_user_remove", project_id,
                lambda: service.update_project_trusted_user(
                project_id,
                user_id,
                add=False,
                actor_id=context.actor_id,
            ).model_dump(mode="json"))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(
                status_code=403,
                detail={"reason_code": "project_owner_required", "message": str(exc)},
            ) from exc

    @router.post("/v1/admin/projects/{project_id}/freeze")
    def freeze_project(
        project_id: str,
        request_body: ProjectFreezeRequest,
        context: AuthContext = Depends(auth.actor),
        action: tuple = Depends(metadata_action_request),
    ) -> dict:
        require_role(context, UserRole.ADMIN)
        try:
            return metadata_mutation(action, context, "project_freeze", project_id,
                lambda: service.set_project_frozen(
                project_id,
                frozen=request_body.frozen,
                reason=request_body.reason,
                actor_id=context.actor_id,
            ).model_dump(mode="json"))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    return router
