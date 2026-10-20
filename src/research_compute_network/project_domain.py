"""Project registration, grants, and trusted-submitter lifecycle."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Protocol

from .control_transactions import atomic_metadata
from .models import (
    ProjectGrant,
    ProjectRegistrationRequest,
    ProjectRegistrationStatus,
    ProjectStatus,
)


EventWriter = Callable[..., None]


class ProjectRepository(Protocol):
    def atomic_write(self): ...
    def put_project_grant(self, grant: ProjectGrant) -> None: ...
    def get_project_grant(self, project_id: str) -> ProjectGrant | None: ...
    def put_project_registration(self, request: ProjectRegistrationRequest) -> None: ...
    def get_project_registration(self, registration_id: str) -> ProjectRegistrationRequest | None: ...
    def list_project_registrations(self) -> list[ProjectRegistrationRequest]: ...
    def list_profiles(self) -> list[Any]: ...
    def get_user(self, user_id: str): ...


class ProjectDomain:
    def __init__(self, repository: ProjectRepository, event_writer: EventWriter) -> None:
        self.repository = repository
        self._event = event_writer

    @atomic_metadata
    def register(self, grant: ProjectGrant, *, actor_id: str) -> ProjectGrant:
        status_is_active = grant.status == ProjectStatus.ACTIVE
        if grant.approved != status_is_active:
            grant.status = ProjectStatus.ACTIVE if grant.approved else ProjectStatus.PENDING
            grant.frozen_reason = ""
        grant.updated_at = datetime.now(timezone.utc)
        self.repository.put_project_grant(grant)
        self._event(
            "project_grant.updated",
            actor_id,
            "project",
            grant.project_id,
            approved=grant.approved,
            status=grant.status.value,
            authorized_user_count=len(grant.authorized_user_ids),
        )
        return grant

    @atomic_metadata
    def request_registration(
        self,
        request: ProjectRegistrationRequest,
        *,
        actor_id: str,
    ) -> ProjectRegistrationRequest:
        if request.requested_by != actor_id:
            raise ValueError("project registration owner must match the authenticated user")
        if self.repository.get_project_grant(request.project_id) is not None:
            raise ValueError("project is already registered")
        pending = [
            item
            for item in self.repository.list_project_registrations()
            if item.project_id == request.project_id
            and item.status == ProjectRegistrationStatus.REQUESTED
        ]
        if pending:
            raise ValueError("project already has a pending registration request")
        known_profiles = {profile.profile_id for profile in self.repository.list_profiles()}
        unknown = request.requested_profiles - known_profiles
        if unknown:
            raise ValueError(f"unknown requested profiles: {', '.join(sorted(unknown))}")
        self.repository.put_project_registration(request)
        self._event(
            "project_registration.requested",
            actor_id,
            "project_registration",
            request.registration_id,
            project_id=request.project_id,
            requested_profiles=sorted(request.requested_profiles),
        )
        return request

    @atomic_metadata
    def review_registration(
        self,
        registration_id: str,
        *,
        approve: bool,
        allowed_profiles: set[str],
        priority_ceiling: int,
        reason: str,
        actor_id: str,
    ) -> ProjectRegistrationRequest:
        request = self.repository.get_project_registration(registration_id)
        if request is None:
            raise KeyError(f"project registration not found: {registration_id}")
        if request.status != ProjectRegistrationStatus.REQUESTED:
            raise ValueError("project registration has already been reviewed")
        now = datetime.now(timezone.utc)
        request.status = (
            ProjectRegistrationStatus.APPROVED
            if approve
            else ProjectRegistrationStatus.REJECTED
        )
        request.reviewed_by = actor_id
        request.review_reason = reason.strip()
        request.updated_at = now
        if approve:
            if not allowed_profiles:
                raise ValueError("an approved project requires at least one Profile")
            unknown = allowed_profiles - {
                profile.profile_id for profile in self.repository.list_profiles()
            }
            if unknown:
                raise ValueError(f"unknown allowed profiles: {', '.join(sorted(unknown))}")
            self.register(
                ProjectGrant(
                    project_id=request.project_id,
                    owner_user_id=request.requested_by,
                    approved=True,
                    status=ProjectStatus.ACTIVE,
                    allowed_profiles=allowed_profiles,
                    max_queued_units=2000,
                    max_running_units=4,
                    priority_ceiling=priority_ceiling,
                ),
                actor_id=actor_id,
            )
        self.repository.put_project_registration(request)
        self._event(
            "project_registration.reviewed",
            actor_id,
            "project_registration",
            registration_id,
            project_id=request.project_id,
            status=request.status.value,
            reason=request.review_reason,
        )
        return request

    @atomic_metadata
    def update_trusted_user(
        self,
        project_id: str,
        user_id: str,
        *,
        add: bool,
        actor_id: str,
    ) -> ProjectGrant:
        grant = self.repository.get_project_grant(project_id)
        if grant is None:
            raise KeyError(f"project grant not found: {project_id}")
        if actor_id != grant.owner_user_id:
            raise PermissionError("only the project owner can manage trusted submitters")
        user = self.repository.get_user(user_id)
        if user is None or not user.active:
            raise KeyError(f"active user not found: {user_id}")
        if add:
            grant.authorized_user_ids.add(user_id)
        else:
            grant.authorized_user_ids.discard(user_id)
        grant.authorized_user_ids.discard(grant.owner_user_id)
        self.register(grant, actor_id=actor_id)
        self._event(
            "project_trusted_user.added" if add else "project_trusted_user.removed",
            actor_id,
            "project",
            project_id,
            user_id=user_id,
        )
        return grant

    @atomic_metadata
    def set_frozen(
        self,
        project_id: str,
        *,
        frozen: bool,
        reason: str,
        actor_id: str,
    ) -> ProjectGrant:
        grant = self.repository.get_project_grant(project_id)
        if grant is None:
            raise KeyError(f"project grant not found: {project_id}")
        grant.status = ProjectStatus.FROZEN if frozen else ProjectStatus.ACTIVE
        grant.approved = not frozen
        grant.frozen_reason = reason.strip() if frozen else ""
        return self.register(grant, actor_id=actor_id)

    def record_access_denied(
        self,
        project_id: str,
        *,
        actor_id: str,
        requested_user_id: str | None = None,
        reason: str,
    ) -> None:
        self._event(
            "project_access.denied",
            actor_id,
            "project",
            project_id,
            requested_user_id=requested_user_id,
            reason=reason,
        )
