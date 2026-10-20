"""One conservative visibility boundary for REST and streamed audit records."""
from __future__ import annotations

from .models import FeatureVisibility, UserRole


class EventVisibility:
    def __init__(self, repository, context):
        self.repository = repository
        self.actor_id = context.actor_id
        self.admin = UserRole.ADMIN in context.roles
        settings = repository.get_feature_settings()
        self.own_only = settings.visibility == FeatureVisibility.OWN_DETAIL or not settings.show_group_job_details
        grants = [g for g in repository.list_project_grants() if g.authorizes(context.actor_id)] if not self.admin else []
        self.projects = {g.project_id for g in grants}
        self.owned_projects = {g.project_id for g in grants if g.owner_user_id == context.actor_id}
        self.machines = {
            machine.machine_id for machine in repository.list_machines()
            if machine.owner_user_id == context.actor_id
        } if not self.admin else set()
        self._jobs = {}

    def _job(self, job_id):
        if job_id not in self._jobs:
            job = self.repository.get_job_index(job_id) if hasattr(self.repository, "get_job_index") else self.repository.get_operational_job(job_id)
            project = job.get("project_id") if isinstance(job, dict) else getattr(job, "project_id", None)
            user = job.get("user_id") if isinstance(job, dict) else getattr(job, "user_id", None)
            self._jobs[job_id] = project in self.projects and (not self.own_only or user == self.actor_id)
        return self._jobs[job_id]

    def allows(self, event):
        if self.admin:
            return True
        details = event.details or {}
        project_ids = set(details.get("project_ids") or [])
        job_ids = set(details.get("job_ids") or [])
        machine_ids = set(details.get("machine_ids") or [])
        for singular, values in (("project_id", project_ids), ("job_id", job_ids), ("machine_id", machine_ids)):
            if details.get(singular):
                values.add(details[singular])
        if event.subject_type == "project":
            project_ids.add(event.subject_id)
        elif event.subject_type == "job":
            job_ids.add(event.subject_id)
        elif event.subject_type == "machine":
            machine_ids.add(event.subject_id)
        # Mixed-resource records must not expose an unauthorized sibling.
        if project_ids and not project_ids <= self.projects:
            return False
        if any(not self._job(job_id) for job_id in job_ids):
            return False
        if self.own_only and project_ids and not job_ids and not project_ids <= self.owned_projects:
            return False
        # A Job's worker identity is part of its own operational history.
        # Machine-control records still belong exclusively to the machine owner.
        if event.subject_type == "machine" and event.subject_id not in self.machines:
            return False
        if machine_ids and not (project_ids or job_ids) and not machine_ids <= self.machines:
            return False
        if project_ids or job_ids or machine_ids:
            return True
        if event.subject_type in {"user", "person", "submission_policy", "credit_account"}:
            return event.subject_id == self.actor_id
        return event.actor_id == self.actor_id and event.subject_type in {"submission_operation", "project_registration"}
