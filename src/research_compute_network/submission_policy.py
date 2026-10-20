"""Person-wide submission authorization, additive to project and owner consent.

No machine approval is created here. A missing personal policy retains the old
project-grant path; only an explicitly approved policy can open a new project.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from datetime import datetime
import threading
from typing import Literal
from weakref import WeakKeyDictionary

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import JSON, String, select, update
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.pool import StaticPool

from .models import AuditEvent, JobStatus, ProjectGrant, ProjectStatus, UserRole, WorkUnitStatus, utc_now
from .repository import Base, EventRow, EventSequenceRow, ProjectGrantRow


class SubmissionPolicyError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class PersonSubmissionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    person_id: str = Field(min_length=1, max_length=160)
    approved: bool = False
    allowed_profiles: set[str] = Field(default_factory=set)
    max_queued_units: int = Field(default=2000, ge=0)
    max_running_units: int = Field(default=4, ge=0)
    priority_ceiling: int = Field(default=0, ge=-100, le=100)
    quota_mode: Literal["shadow", "unlimited", "metered"] = "shadow"
    paused: bool = False
    auto_project: bool = True
    updated_at: datetime = Field(default_factory=utc_now)


class PersonSubmissionPolicyRow(Base):
    __tablename__ = "person_submission_policies"
    person_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)


_engine_locks = WeakKeyDictionary()
_engine_locks_guard = threading.Lock()


@contextmanager
def _serialized_write(repository):
    """Serialize the shared in-memory SQLite connection and lock file DB writes.

    File-backed SQLite's IMMEDIATE transaction is the cross-process authority.
    Callers on PostgreSQL additionally lock their existing authoritative row.
    """
    with _engine_locks_guard:
        lock = _engine_locks.setdefault(repository.engine, threading.RLock())
    # A file DB already serializes writers. Holding a Python lock while waiting
    # for its SQL writer can deadlock a caller that entered atomic_write first.
    guard = lock if isinstance(repository.engine.pool, StaticPool) else nullcontext()
    if hasattr(repository, "atomic_write"):
        with guard, repository.atomic_write(), repository._session() as session:
            yield session
            session.flush()
    else:
        with guard, repository._session() as session:
            if repository.engine.dialect.name == "sqlite":
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            try:
                yield session
                session.commit()
            except BaseException:
                session.rollback()
                raise


def _append_audit(session, event_type: str, actor_id: str, subject_type: str, subject_id: str, **details):
    """Commit policy/ledger mutations and their ordinary audit event together."""
    sequence = session.execute(
        update(EventSequenceRow).where(EventSequenceRow.sequence_id == "global")
        .values(next_sequence=EventSequenceRow.next_sequence + 1)
        .returning(EventSequenceRow.next_sequence)
    ).scalar_one() - 1
    event = AuditEvent(event_type=event_type, actor_id=actor_id, subject_type=subject_type,
                       subject_id=subject_id, details=details, sequence=sequence)
    session.add(EventRow(event_id=event.event_id, event_type=event.event_type,
                         subject_type=event.subject_type, subject_id=event.subject_id,
                         created_at=event.created_at, sequence=sequence,
                         payload=event.model_dump(mode="json")))


def _require_admin(repository, actor_id: str) -> None:
    user = repository.get_user(actor_id)
    if actor_id != "local-pilot" and (not user or not user.active or UserRole.ADMIN not in user.roles):
        raise SubmissionPolicyError("admin_required")


class SubmissionPolicyStore:
    def __init__(self, repository):
        self.repository = repository
        if not getattr(repository, "_transaction_session", lambda: None)():
            Base.metadata.create_all(repository.engine, tables=[PersonSubmissionPolicyRow.__table__])

    def get_policy(self, person_id: str) -> PersonSubmissionPolicy | None:
        with self.repository._session() as session:
            row = session.get(PersonSubmissionPolicyRow, person_id)
            return PersonSubmissionPolicy.model_validate(row.payload) if row else None

    def set_policy(self, policy: PersonSubmissionPolicy, *, actor_id: str) -> PersonSubmissionPolicy:
        _require_admin(self.repository, actor_id)
        user = self.repository.get_user(policy.person_id)
        if not user or not user.active or not ({UserRole.MEMBER, UserRole.ADMIN} & user.roles):
            raise SubmissionPolicyError("submission_person_not_active_member")
        if policy.allowed_profiles - {p.profile_id for p in self.repository.list_profiles()}:
            raise SubmissionPolicyError("submission_profile_not_registered")
        policy = policy.model_copy(update={"updated_at": utc_now()})
        with _serialized_write(self.repository) as session:
            row = session.get(PersonSubmissionPolicyRow, policy.person_id) or PersonSubmissionPolicyRow(person_id=policy.person_id)
            before = row.payload if row.payload else None
            row.payload = policy.model_dump(mode="json")
            session.add(row)
            _append_audit(session, "person_submission_policy.updated", actor_id, "person", policy.person_id,
                          before=before, policy=row.payload)
        return policy

    def _approved_policy(self, requester_id: str) -> PersonSubmissionPolicy | None:
        policy = self.get_policy(requester_id)
        if policy is None:
            return None
        user = self.repository.get_user(requester_id)
        if not user or not user.active or not ({UserRole.MEMBER, UserRole.ADMIN} & user.roles):
            raise SubmissionPolicyError("submission_person_not_active_member")
        if not policy.approved:
            raise SubmissionPolicyError("person_submission_not_approved")
        if policy.paused:
            raise SubmissionPolicyError("person_submission_paused")
        return policy

    def effective_project_grant(self, requester_id: str, project_id: str, *, profile_id: str | None = None,
                                priority: int | None = None) -> ProjectGrant | None:
        policy = self._approved_policy(requester_id)
        grant = self.repository.get_project_grant(project_id)
        if policy is None:
            return grant
        if grant is None:
            if not policy.auto_project:
                return None
            grant = ProjectGrant(project_id=project_id, owner_user_id=requester_id,
                                 status=ProjectStatus.ACTIVE, allowed_profiles=policy.allowed_profiles,
                                 max_queued_units=max(1, policy.max_queued_units),
                                 max_running_units=max(1, policy.max_running_units),
                                 priority_ceiling=policy.priority_ceiling, person_policy_inherited=True)
        elif getattr(grant, "person_policy_inherited", False):
            owner_policy = policy if grant.owner_user_id == requester_id else self.get_policy(grant.owner_user_id)
            # A collaborator's broader personal Profile list cannot expand an
            # auto project's owner-derived scope. Explicit grants use the
            # separate intersection branch below.
            inherited_profiles = owner_policy.allowed_profiles if owner_policy else grant.allowed_profiles
            inherited_queued = owner_policy.max_queued_units if owner_policy else grant.max_queued_units
            inherited_running = owner_policy.max_running_units if owner_policy else grant.max_running_units
            inherited_priority = owner_policy.priority_ceiling if owner_policy else grant.priority_ceiling
            grant = grant.model_copy(deep=True, update={
                "allowed_profiles": inherited_profiles & policy.allowed_profiles,
                "max_queued_units": max(1, min(inherited_queued, policy.max_queued_units)),
                "max_running_units": max(1, min(inherited_running, policy.max_running_units)),
                "priority_ceiling": min(inherited_priority, policy.priority_ceiling),
            })
        else:
            grant = grant.model_copy(deep=True, update={
                "allowed_profiles": grant.allowed_profiles & policy.allowed_profiles,
                "max_queued_units": max(1, min(grant.max_queued_units, policy.max_queued_units)),
                "max_running_units": max(1, min(grant.max_running_units, policy.max_running_units)),
                "priority_ceiling": min(grant.priority_ceiling, policy.priority_ceiling),
            })
        if profile_id is not None and profile_id not in policy.allowed_profiles:
            raise SubmissionPolicyError("person_profile_not_allowed")
        if priority is not None and priority > policy.priority_ceiling:
            raise SubmissionPolicyError("person_priority_ceiling_exceeded")
        return grant

    def authorize(self, requester_id: str, profile_id: str, project_id: str, *, priority: int | None = None,
                  queued_units: int = 0, exclude_job_id: str | None = None) -> ProjectGrant:
        if queued_units < 0:
            raise ValueError("queued_units must be nonnegative")
        grant = self.effective_project_grant(requester_id, project_id, profile_id=profile_id, priority=priority)
        if grant is None:
            raise SubmissionPolicyError("project_not_approved")
        if not grant.permits_submission(requester_id):
            raise SubmissionPolicyError("project_submission_not_allowed")
        if profile_id not in grant.allowed_profiles:
            raise SubmissionPolicyError("project_profile_not_allowed")
        if priority is not None and priority > grant.priority_ceiling:
            raise SubmissionPolicyError("project_priority_ceiling_exceeded")
        policy = self.get_policy(requester_id)
        if policy is not None and queued_units:
            usage = self.aggregate_usage(requester_id, exclude_job_id=exclude_job_id)
            if usage["queued_units"] + queued_units > policy.max_queued_units:
                raise SubmissionPolicyError("person_queued_unit_cap_exceeded")
        return grant

    def aggregate_usage(self, person_id: str, *, exclude_job_id: str | None = None) -> dict[str, int]:
        queued = running = 0
        jobs = self.repository.list_operational_jobs(
            statuses=[JobStatus.AWAITING_APPROVAL, JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.FAILED_RETRIABLE],
            user_id=person_id)
        for job in jobs:
            if job.job_id == exclude_job_id:
                continue
            for unit in job.work_units:
                queued += unit.status in {WorkUnitStatus.QUEUED, WorkUnitStatus.FAILED_RETRIABLE}
                running += unit.status in {WorkUnitStatus.ASSIGNED, WorkUnitStatus.RUNNING,
                                           WorkUnitStatus.RECONCILE_PENDING, WorkUnitStatus.COLLECTING}
        # Prepared reservations occupy the same person's future execution budget.
        # A reservation already activated into an Attempt is not counted twice.
        owned_jobs = {job.job_id: job for job in jobs if job.job_id != exclude_job_id}
        prepared = 0
        for reservation in self.repository.list_dispatch_reservations(active_only=True):
            job = owned_jobs.get(reservation.job_id)
            if job is None:
                continue
            unit = next((u for u in job.work_units if u.work_unit_id == reservation.work_unit_id), None)
            if unit is not None and unit.status == WorkUnitStatus.QUEUED:
                prepared += 1
        return {"queued_units": queued, "running_units": running + prepared, "prepared_units": prepared}

    def check_running_capacity(self, person_id: str, *, additional_units: int = 1,
                               running_units: int | None = None) -> None:
        if additional_units < 0:
            raise ValueError("additional_units must be nonnegative")
        policy = self._approved_policy(person_id)
        if policy is None:
            return
        current = self.aggregate_usage(person_id)["running_units"] if running_units is None else running_units
        if current + additional_units > policy.max_running_units:
            raise SubmissionPolicyError("person_running_unit_cap_exceeded")

    def auto_register_project(self, requester_id: str, project_id: str, *, profile_id: str | None = None) -> ProjectGrant:
        policy = self._approved_policy(requester_id)
        if policy is None or not policy.auto_project:
            raise SubmissionPolicyError("person_auto_project_not_enabled")
        if profile_id is not None and profile_id not in policy.allowed_profiles:
            raise SubmissionPolicyError("person_profile_not_allowed")
        # Validate the same public project identifier contract as registration.
        from .models import ProjectRegistrationRequest
        ProjectRegistrationRequest(project_id=project_id, requested_by=requester_id,
                                   display_name=project_id, purpose="Personal project registration")
        with _serialized_write(self.repository) as session:
            row = session.scalar(select(ProjectGrantRow).where(ProjectGrantRow.project_id == project_id).with_for_update())
            if row is not None:
                grant = ProjectGrant.model_validate(row.payload)
                if not grant.permits_submission(requester_id):
                    raise SubmissionPolicyError("project_submission_not_allowed")
                return grant
            grant = ProjectGrant(project_id=project_id, owner_user_id=requester_id,
                                 status=ProjectStatus.ACTIVE, allowed_profiles=policy.allowed_profiles,
                                 max_queued_units=max(1, policy.max_queued_units),
                                 max_running_units=max(1, policy.max_running_units), priority_ceiling=policy.priority_ceiling,
                                 person_policy_inherited=True)
            session.add(ProjectGrantRow(project_id=project_id, approved=True, payload=grant.model_dump(mode="json")))
            _append_audit(session, "project.auto_registered", requester_id, "project", project_id,
                          person_id=requester_id, policy_updated_at=policy.updated_at.isoformat())
        return grant

    def effective_policy(self, person_id: str) -> dict:
        policy = self.get_policy(person_id)
        return {"person_id": person_id, "source": "person" if policy else "legacy_project_grants",
                "policy": policy.model_dump(mode="json") if policy else None,
                "usage": self.aggregate_usage(person_id)}
