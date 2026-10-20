"""Execution consumers of personal policies; projects remain provenance identities."""
from __future__ import annotations

from .hashing import sha256_value
from .models import SolverCompatibilityApproval, SolverMeshPolicy, SolverVariant, UserRole
from .submission_policy import PersonSubmissionPolicy, SubmissionPolicyError, SubmissionPolicyStore


def policy_store(service):
    if not hasattr(service, "_personal_policy_store"):
        service._personal_policy_store = SubmissionPolicyStore(service.repository)
    return service._personal_policy_store


def bootstrap_person(service, person_id):
    store = policy_store(service)
    policy = store.get_policy(person_id)
    user = service.repository.get_user(person_id)
    if policy is not None or user is None or not user.active or not (user.roles & {UserRole.MEMBER, UserRole.ADMIN}):
        return policy
    grants = [grant for grant in service.repository.list_project_grants() if grant.authorizes(person_id) and grant.approved]
    profiles = set().union(*(grant.allowed_profiles for grant in grants)) if grants else {
        profile.profile_id for profile in service.repository.list_profiles()
        if profile.profile_id != "project-worker-v1" and not profile.allow_arbitrary_command
    }
    admin = UserRole.ADMIN in user.roles
    policy = PersonSubmissionPolicy(person_id=person_id, approved=True,
        allowed_profiles=profiles,
        max_queued_units=max(2000, sum(g.max_queued_units for g in grants)),
        max_running_units=max(4, sum(g.max_running_units for g in grants)),
        priority_ceiling=100 if admin else max((g.priority_ceiling for g in grants), default=0),
        quota_mode="unlimited" if admin else "shadow")
    return store.set_policy(policy, actor_id="local-pilot")


def authorize_request(service, request, *, queued_units=0, actor_id=None):
    bootstrap_person(service, request.user_id)
    store = policy_store(service)
    actor = service.repository.get_user(actor_id) if actor_id else None
    if actor_id != request.user_id and actor is not None and UserRole.ADMIN in actor.roles:
        grant = service.repository.get_project_grant(request.project_id)
        if grant is not None and grant.approved and request.execution_profile_id in grant.allowed_profiles:
            return grant
    if store.get_policy(request.user_id) is None:
        return service.repository.get_project_grant(request.project_id)
    try:
        if service.repository.get_project_grant(request.project_id) is None:
            store.auto_register_project(request.user_id, request.project_id,
                profile_id=request.execution_profile_id)
        return store.authorize(request.user_id, request.execution_profile_id, request.project_id,
            queued_units=queued_units, exclude_job_id=getattr(request, "job_id", None))
    except SubmissionPolicyError as exc:
        from .service import ExecutionCompatibilityError
        raise ExecutionCompatibilityError(exc.reason_code, str(exc)) from exc


def execution_binding(service, request):
    """Bind approved fixed executors to exact data; this is not scientific acceptance."""
    policy = policy_store(service).get_policy(request.user_id)
    if policy is None or not policy.approved or policy.paused:
        return
    if not service._solver_approval_required(request.execution_profile_id, request.allowed_solver_variants):
        return
    if request.solver_approval_id:
        # Explicit revoked or mismatched bindings must never be resurrected.
        return
    payloads = [item.payload for item in request.items]
    try:
        service._resolve_solver_approval(project_id=request.project_id,
            execution_profile_id=request.execution_profile_id,
            allowed_solver_variants=request.allowed_solver_variants,
            item_payloads=payloads, hint_approval_id=None)
        return
    except Exception as exc:
        if getattr(exc, "reason_code", None) != "no_current_runtime_approval":
            raise
    template_sha = request.template_sha256 or next((p.get("template_sha256") for p in payloads if p.get("template_sha256")), None)
    if template_sha is None:
        return
    special = request.execution_profile_id in {"workbench-comsol-template-build-v1", "workbench-comsol-saved-readout-v1"}
    mesh_policy = None
    if request.execution_profile_id == "workbench-comsol-template-build-v1":
        from .remote_agent.template_build_contracts import TEMPLATE_BUILD_MESH_POLICY
        mesh_policy = SolverMeshPolicy.model_validate(TEMPLATE_BUILD_MESH_POLICY)
    elif request.execution_profile_id != "workbench-comsol-saved-readout-v1":
        first = payloads[0] if payloads else {}
        container = first.get("study") if request.execution_profile_id in {
            "workbench-comsol-study-v1", "workbench-comsol-study-v2"
        } else first.get("recipe_config")
        if isinstance(container, dict) and container.get("mesh_policy") is not None:
            mesh_policy = SolverMeshPolicy.model_validate(container["mesh_policy"])
    fields = dict(project_id=request.project_id, execution_profile_id=request.execution_profile_id,
        comsol_version="6.4", runtime_version=service.runtime_policy.stable_runtime_version,
        template_sha256=template_sha, template_role=request.template_role,
        allowed_study_kinds={request.study_kind} if request.study_kind else set(),
        mesh_policy=mesh_policy,
        solver_variants={SolverVariant.MUMPS} if special else {SolverVariant.MUMPS, SolverVariant.CUDSS},
        approved_by="person-policy:" + request.user_id)
    approval = SolverCompatibilityApproval(**fields)
    # The reviewed fingerprint canonicalizes sets and nested policy fields.
    # Hashing Python set/model reprs would change this identity across restarts.
    approval.approval_id = "solver-person-" + sha256_value({
        "person_id": request.user_id, "fingerprint": approval.fingerprint,
    })[:32]
    service._validate_solver_approval_evidence(approval, request.execution_profile_id, payloads)
    original = service.approve_solver(approval, actor_id="person-policy:" + request.user_id)
    if not original.is_active():
        from .service import ExecutionCompatibilityError
        raise ExecutionCompatibilityError("execution_binding_revoked",
            "the original exact execution binding was revoked; administrator review is required")
    service._event("person_execution_binding.authorized", request.user_id, "project", request.project_id,
        approval_id=approval.approval_id, policy_person_id=request.user_id,
        scientific_acceptance=False)


def effective_job_grant(service, job):
    store = policy_store(service)
    try:
        grant = store.effective_project_grant(job.user_id, job.project_id,
            profile_id=job.execution_profile_id)
        return grant
    except SubmissionPolicyError:
        grant = service.repository.get_project_grant(job.project_id)
        return grant.model_copy(update={"approved": False}) if grant is not None else None


def reserve_attempt(service, job, unit, attempt):
    from .compute_credits import ComputeCredits, CreditError
    from .models import utc_now
    store = policy_store(service)
    if store.get_policy(job.user_id) is None:
        return None
    store.check_running_capacity(job.user_id, additional_units=0 if attempt.dispatch_reservation_id else 1)
    credits = getattr(service, "_compute_credits", None) or ComputeCredits(service.repository)
    try:
        return credits.reserve_attempt(job, unit, attempt)
    except CreditError as exc:
        if exc.reason_code not in {"insufficient_compute_credits", "mutual_pool_disabled_by_owner"}:
            raise
        # This opt-in pool cannot mint exchange credit and cannot interrupt work.
        return credits.reserve_attempt(job, unit, attempt, pool="free_idle")


def settle_after(function):
    from functools import wraps
    from inspect import signature
    @wraps(function)
    def wrapped(self, *args, **kwargs):
        job = function(self, *args, **kwargs)
        if job is not None and hasattr(job, "work_units"):
            arguments = signature(function).bind(self, *args, **kwargs).arguments
            unit_id = arguments.get("work_unit_id")
            if unit_id is None:
                unit_id = next((getattr(value, "work_unit_id") for value in arguments.values()
                                if hasattr(value, "work_unit_id")), None)
            settle_job(self, job, unit_id=unit_id)
        return job
    return wrapped


def settle_job(service, job, *, unit_id=None):
    from .compute_credits import ComputeCredits
    credits = getattr(service, "_compute_credits", None) or ComputeCredits(service.repository)
    for unit in job.work_units:
        if unit_id is not None and unit.work_unit_id != unit_id:
            continue
        for attempt in unit.attempts:
            if attempt.state in {"completed", "failed", "cancelled", "abandoned"}:
                credits.settle_attempt(job, unit, attempt)
