"""Control-plane application service."""

from __future__ import annotations

from .shared_capacity import SharedCapacityConflict
from .mutation_receipts import (credential_confirmation, admin_confirmation,
    solver_approval_confirmation, alert_transition_confirmation)
from .pressure_transactions import pressure_confirmation
from .unit_reassignment import fenced_reassignment
from .storage_io import io_priority

import copy
import hashlib
import copy
import hmac
import json
import math
import os
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from .connection_health import StaleMachineObservationError, fresh
from .models import (
    AlertRecord,
    AlertSeverity,
    AlertStatus,
    AdminOperation,
    AdminOperationTicket,
    ApprovalRecord,
    ApiTokenRecord,
    ArtifactManifest,
    Assignment,
    AuditEvent,
    BreakGlassConfig,
    ControlOperationRun,
    ControlOperationState,
    ControlState,
    ControlTargetResult,
    ControlTargetState,
    DispatcherControlAction,
    DispatcherControlTicket,
    DispatchReservation,
    EnrollmentRecord,
    ExternalLoadSnapshot,
    ExecutionProfile,
    FailureClass,
    FeatureSettings,
    GpuMetric,
    HeartbeatPhase,
    JobEnvelope,
    JobStatus,
    MachineAgentCredential,
    MachineCommand,
    MachineControlAction,
    MachineControlTarget,
    MachineControlTicket,
    MachineHeartbeat,
    ChannelObservation,
    MachineMetrics,
    MachineMode,
    MachinePreflightRun,
    MachinePolicy,
    MachineState,
    MachineExecutionConfig,
    MachineOperationalStatus,
    OriginImportReceipt,
    OriginAdapterRegistration,
    PressureOverrideTicket,
    PressureState,
    ResolvedResources,
    ResourcePolicy,
    ResourceMode,
    MetricSample,
    PartitionPlan,
    PartitionRequest,
    ProjectGrant,
    ProjectRegistrationRequest,
    ProjectStatus,
    RemoteRunRecord,
    RemoteRunState,
    SshAcceptanceRun,
    SolverCompatibilityApproval,
    SolverMeshPolicy,
    SolverPolicy,
    SolverVariant,
    SupervisorState,
    TelemetryState,
    TransportState,
    IssuedToken,
    IssuedEnrollment,
    PlacementConstraint,
    UserAccount,
    WorkUnitAttempt,
    WorkUnit,
    WorkUnitStatus,
    derived_job_status,
)
from .hashing import sha256_value
from .failure_diagnostics import (
    is_deterministic_scientific_failure, is_worker_termination_failure,
    is_native_file_io_failure, is_storage_exhaustion_failure,
)
from .machine_observation import (
    MachineObservationApplication,
    MachineObservationResult,
    finalize_operational_status,
)
from .parameter_guard import (
    GENERIC_STUDY_PROFILE_ID,
    GENERIC_STUDY_PROFILE_IDS,
    validate_job_parameter_contract,
    validate_partition_parameter_contract,
)
from .remote_agent.template_build_contracts import (
    TEMPLATE_BUILD_PROFILE_ID, TEMPLATE_BUILD_MESH_POLICY,
    template_build_preset_contract,
)

from .remote_agent.saved_readout_contracts import (
    SAVED_READOUT_PROFILE_ID, saved_readout_contract,
    saved_readout_source_contract,
)

SEALED_COMSOL_PROFILE_IDS = GENERIC_STUDY_PROFILE_IDS | {TEMPLATE_BUILD_PROFILE_ID, SAVED_READOUT_PROFILE_ID}
from .placement import MachinePlacementEvaluation, PlacementBlocker, evaluate_placement
from .partitioning import confirm_partition_plan, create_partition_plan, job_from_confirmed_plan
from .profiles import BUILTIN_PROFILES
from .project_domain import ProjectDomain
from .resource_policy import default_resource_policy, recommend_adaptive_policy, resolve_resources
from .submission_policy import SubmissionPolicyError
from .compute_credits import CreditError
from .personal_runtime import settle_after
from .control_transactions import atomic_confirmation, atomic_metadata
from .repository import MetadataRepository, PolicyRevisionConflict, _validate_policy_payload_sha256
from .remote_storage import validate_remote_root_path
from .runtime_policy import (
    DEFAULT_RUNTIME_POLICY,
    LEGACY_SEALED_RUNTIME_VERSION,
    PACKAGE_VERSION,
    PROTOCOL_VERSION,
    STABLE_RUNTIME_VERSION,
    RuntimePolicy,
)

# A prepared standby defers to strictly higher-ranked waiters, but deferral
# must be bounded: against a deep, continuously refilled queue it would
# otherwise never activate. After this many seconds the standby stops
# deferring and takes the next genuinely free slot.
STANDBY_STARVATION_GUARD_S = 900


class _AssignmentStateChanged(RuntimeError):
    pass


class ExecutionCompatibilityError(ValueError):
    """A valid scientific request cannot execute in the current environment."""

    def __init__(self, reason_code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message
        self.details = details

    def detail(self) -> dict[str, str]:
        return {"reason_code": self.reason_code, "message": self.message, **self.details}


def configure_canary_runtime_versions(
    versions: list[str] | tuple[str, ...] | set[str],
) -> RuntimePolicy:
    """Compatibility constructor; it no longer mutates process-global state."""

    return RuntimePolicy.with_candidates(versions)


def supported_worker_runtime_versions(
    policy: RuntimePolicy | None = None,
) -> frozenset[str]:
    return (policy or DEFAULT_RUNTIME_POLICY).worker_runtime_versions


def accepted_solver_runtime_versions(
    policy: RuntimePolicy | None = None,
) -> frozenset[str]:
    return (policy or DEFAULT_RUNTIME_POLICY).approval_runtime_versions


class _DispatchHydrationCache:
    """One hydrated Job per selection pass, never shared across mutations."""

    def __init__(self, repository):
        self.repository = repository
        self.jobs = {}

    def get(self, job_id, unit_id):
        if job_id not in self.jobs:
            job = self.repository.get_job(job_id)
            self.jobs[job_id] = (job, {unit.work_unit_id: unit for unit in job.work_units} if job else {})
        job, units = self.jobs[job_id]
        return job, units.get(unit_id)


class _DispatchApprovalSnapshot:
    """Metadata for one scan; scientific bindings are validated per Unit."""

    def __init__(self, repository):
        approvals = repository.list_solver_approvals()
        self.by_id = {approval.approval_id: approval for approval in approvals}
        self.by_project: dict[str, list[SolverCompatibilityApproval]] = {}
        for approval in approvals:
            if approval.active:
                self.by_project.setdefault(approval.project_id, []).append(approval)


class NetworkService:
    def __init__(
        self,
        repository: MetadataRepository,
        *,
        runtime_policy: RuntimePolicy | None = None,
    ) -> None:
        self.repository = repository
        from .runtime_policy import runtime_policy_from_environment
        self.runtime_policy = runtime_policy or runtime_policy_from_environment()
        from .member_release_catalog import selected_center_release
        self.member_release = selected_center_release()
        if self.member_release.owner_session_required and self.member_release.runtime_version != self.runtime_policy.stable_runtime_version:
            self.runtime_policy = RuntimePolicy(
                stable_runtime_version=self.runtime_policy.stable_runtime_version,
                legacy_runtime_versions=self.runtime_policy.legacy_runtime_versions,
                candidate_runtime_versions=self.runtime_policy.candidate_runtime_versions | {self.member_release.runtime_version},
            )
        self.machine_observations = MachineObservationApplication(repository)
        self.projects = ProjectDomain(repository, self._event)
        self._unknown_failure_backfill_complete = False

    def initialize(self, *, dataset_mode: str = "formal") -> None:
        self.repository.init_schema()
        from .submission_policy import SubmissionPolicyStore
        from .compute_credits import ComputeCredits
        self._personal_policy_store = SubmissionPolicyStore(self.repository)
        self._compute_credits = ComputeCredits(self.repository)
        self.repository.ensure_dataset_mode(dataset_mode)
        for profile in BUILTIN_PROFILES.values():
            self.repository.put_profile(profile)
        built_in_adapters = (
            OriginAdapterRegistration(
                adapter_id="workbench",
                version="0.13.0",
                allowed_profile_ids={
                    profile_id for profile_id in BUILTIN_PROFILES
                    if profile_id != "project-worker-v1"
                },
                registered_by="system",
            ),
            OriginAdapterRegistration(
                adapter_id="project-worker-v1",
                version="1",
                contract_kind="legacy-read-only",
                active=True,
                accepts_new_submissions=False,
                registered_by="system",
            ),
        )
        for adapter in built_in_adapters:
            if self.repository.get_origin_adapter(adapter.adapter_id) is None:
                self.repository.put_origin_adapter(adapter)
        self.register_member_runtime_successors(actor_id="member-release-initializer")
        from .personal_runtime import bootstrap_person
        for user in self.repository.list_users():
            bootstrap_person(self, user.user_id)



    @atomic_metadata
    def create_profile_version(
        self,
        profile: ExecutionProfile,
        *,
        actor_id: str,
    ) -> ExecutionProfile:
        existing = self.repository.get_profile(profile.profile_id)
        if existing is not None:
            if existing != profile:
                raise ValueError("execution profiles are immutable; create a new profile ID/version")
            return existing
        self.repository.put_profile(profile)
        self._event(
            "execution_profile.created",
            actor_id,
            "execution_profile",
            profile.profile_id,
            version=profile.version,
            executor_kind=profile.executor_kind,
        )
        return profile

    def _event(
        self,
        event_type: str,
        actor_id: str,
        subject_type: str,
        subject_id: str,
        **details,
    ) -> None:
        self.repository.append_event(AuditEvent(
            event_type=event_type,
            actor_id=actor_id,
            subject_type=subject_type,
            subject_id=subject_id,
            details=details,
        ))

    def register_project(self, grant: ProjectGrant, *, actor_id: str) -> ProjectGrant:
        return self.projects.register(grant, actor_id=actor_id)

    def request_project_registration(
        self,
        request: ProjectRegistrationRequest,
        *,
        actor_id: str,
    ) -> ProjectRegistrationRequest:
        return self.projects.request_registration(request, actor_id=actor_id)

    def review_project_registration(
        self,
        registration_id: str,
        *,
        approve: bool,
        allowed_profiles: set[str],
        priority_ceiling: int,
        reason: str,
        actor_id: str,
    ) -> ProjectRegistrationRequest:
        return self.projects.review_registration(
            registration_id,
            approve=approve,
            allowed_profiles=allowed_profiles,
            priority_ceiling=priority_ceiling,
            reason=reason,
            actor_id=actor_id,
        )

    def update_project_trusted_user(
        self,
        project_id: str,
        user_id: str,
        *,
        add: bool,
        actor_id: str,
    ) -> ProjectGrant:
        return self.projects.update_trusted_user(
            project_id,
            user_id,
            add=add,
            actor_id=actor_id,
        )

    def set_project_frozen(
        self,
        project_id: str,
        *,
        frozen: bool,
        reason: str,
        actor_id: str,
    ) -> ProjectGrant:
        return self.projects.set_frozen(
            project_id,
            frozen=frozen,
            reason=reason,
            actor_id=actor_id,
        )

    def record_project_access_denied(
        self,
        project_id: str,
        *,
        actor_id: str,
        requested_user_id: str | None = None,
        reason: str,
    ) -> None:
        return self.projects.record_access_denied(
            project_id,
            actor_id=actor_id,
            requested_user_id=requested_user_id,
            reason=reason,
        )

    @atomic_metadata
    def create_user(self, user: UserAccount, *, actor_id: str) -> UserAccount:
        self.repository.put_user(user)
        from .personal_runtime import bootstrap_person
        bootstrap_person(self, user.user_id)
        self._event("user.updated", actor_id, "user", user.user_id, roles=sorted(role.value for role in user.roles))
        return user

    @credential_confirmation
    def issue_token(self, user_id: str, *, actor_id: str, agent: bool = False) -> IssuedToken:
        user = self.repository.get_user(user_id)
        if user is None or not user.active:
            raise KeyError(f"active user not found: {user_id}")
        secret = secrets.token_urlsafe(32)
        record = ApiTokenRecord(
            user_id=user_id,
            token_hash=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
            scopes={"api", "agent"} if agent else {"api"},
        )
        self.repository.put_token(record)
        self._event("api_token.issued", actor_id, "user", user_id, token_id=record.token_id,
                    scopes=sorted(record.scopes))
        return IssuedToken(token_id=record.token_id, user_id=user_id, token=secret)

    def issue_machine_credential(self, machine_id: str, *, actor_id: str) -> IssuedToken:
        if self.repository.get_machine(machine_id) is None:
            raise KeyError(f"machine not found: {machine_id}")
        secret = secrets.token_urlsafe(32)
        credential = MachineAgentCredential(
            machine_id=machine_id,
            token_hash=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
            issued_by=actor_id,
        )
        self.repository.put_machine_credential(credential)
        self._event(
            "machine_agent_credential.issued",
            actor_id,
            "machine",
            machine_id,
            credential_id=credential.credential_id,
        )
        return IssuedToken(token_id=credential.credential_id, user_id=machine_id, token=secret)

    def issue_enrollment(
        self,
        owner_user_id: str,
        *,
        actor_id: str,
        ttl_minutes: int = 30,
    ) -> IssuedEnrollment:
        if ttl_minutes < 1 or ttl_minutes > 1440:
            raise ValueError("enrollment TTL must be between 1 and 1440 minutes")
        owner = self.repository.get_user(owner_user_id)
        if owner is None or not owner.active:
            raise KeyError(f"active enrollment owner not found: {owner_user_id}")
        secret = secrets.token_urlsafe(24)
        record = EnrollmentRecord(
            code_hash=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
            issued_by=actor_id,
            owner_user_id=owner_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes),
        )
        self.repository.put_enrollment(record)
        self._event(
            "node.enrollment_issued",
            actor_id,
            "enrollment",
            record.enrollment_id,
            owner_user_id=owner_user_id,
            expires_at=record.expires_at.isoformat(),
        )
        return IssuedEnrollment(
            enrollment_id=record.enrollment_id,
            enrollment_code=secret,
            expires_at=record.expires_at,
        )

    def issue_self_enrollment(
        self,
        owner_user_id: str,
        *,
        ttl_minutes: int = 30,
        limit_per_hour: int = 3,
    ) -> IssuedEnrollment:
        now = datetime.now(timezone.utc)
        recent = [
            item for item in self.repository.list_enrollments(owner_user_id=owner_user_id)
            if item.created_at >= now - timedelta(hours=1)
        ]
        if len(recent) >= limit_per_hour:
            raise ValueError("self-service enrollment rate limit exceeded")
        return self.issue_enrollment(
            owner_user_id,
            actor_id=owner_user_id,
            ttl_minutes=ttl_minutes,
        )

    @atomic_metadata
    def set_external_comsol_consent(
        self,
        machine_id: str,
        *,
        authorized: bool,
        actor_id: str,
    ) -> MachinePolicy:
        policy = self.repository.get_policy(machine_id)
        if policy is None:
            raise KeyError(f"machine policy not found: {machine_id}")
        policy.external_comsol_termination_authorized = authorized
        policy.external_comsol_consent_updated_by = actor_id
        policy.external_comsol_consent_updated_at = datetime.now(timezone.utc)
        policy.updated_at = policy.external_comsol_consent_updated_at
        self.repository.put_policy(policy)
        self._event(
            "machine.external_comsol_consent.updated",
            actor_id,
            "machine",
            machine_id,
            authorized=authorized,
        )
        return policy

    def enroll_machine(self, code: str, machine: MachineState) -> tuple[MachineState, IssuedToken]:
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        record = self.repository.get_enrollment_by_code_hash(code_hash)
        if record is None or not record.is_available():
            raise ValueError("enrollment code is invalid, expired, or already used")
        if machine.owner_user_id != record.owner_user_id:
            raise ValueError("machine owner does not match enrollment owner")
        if machine.protocol_version != PROTOCOL_VERSION:
            raise ValueError(
                f"incompatible protocol {machine.protocol_version}; expected {PROTOCOL_VERSION}"
            )
        if "worker" in machine.capabilities and not self.runtime_policy.accepts_worker_runtime(
            machine.runtime_version
        ):
            raise ValueError(
                f"incompatible worker runtime {machine.runtime_version!r}; expected {STABLE_RUNTIME_VERSION}"
            )
        if self.repository.get_machine(machine.machine_id) is not None:
            raise ValueError(f"machine is already registered: {machine.machine_id}")
        policy = MachinePolicy(
            machine_id=machine.machine_id,
            owner_user_id=machine.owner_user_id,
            owner_mode=MachineMode.PAUSED,
        )
        record = self.repository.consume_enrollment(
            record,
            machine_id=machine.machine_id,
            hostname=machine.hostname,
            capabilities=set(machine.capabilities),
        )
        if record is None:
            raise ValueError("enrollment code is invalid, expired, or already used")
        self.register_machine(machine, policy, actor_id=f"enrollment:{record.enrollment_id}")
        credential = self.issue_machine_credential(
            machine.machine_id,
            actor_id=f"enrollment:{record.enrollment_id}",
        )
        self._event(
            "node.enrolled",
            f"enrollment:{record.enrollment_id}",
            "machine",
            machine.machine_id,
            owner_user_id=machine.owner_user_id,
            protocol_version=machine.protocol_version,
            runtime_version=machine.runtime_version,
        )
        return machine, credential

    def revoke_machine_credential(
        self,
        machine_id: str,
        credential_id: str,
        *,
        actor_id: str,
    ) -> MachineAgentCredential:
        credential = self.repository.get_machine_credential(credential_id)
        if credential is None or credential.machine_id != machine_id:
            raise KeyError(f"machine credential not found: {credential_id}")
        credential.active = False
        self.repository.put_machine_credential(credential)
        self._event(
            "machine_agent_credential.revoked",
            actor_id,
            "machine",
            machine_id,
            credential_id=credential_id,
        )
        return credential

    @atomic_metadata
    def register_machine(
        self,
        machine: MachineState,
        policy: MachinePolicy,
        *,
        actor_id: str,
    ) -> MachineState:
        if machine.machine_id != policy.machine_id:
            raise ValueError("machine and policy IDs must match")
        if machine.owner_user_id != policy.owner_user_id:
            raise ValueError("machine and policy owner IDs must match")
        previous_machine = self.repository.get_machine(machine.machine_id)
        if previous_machine is not None and previous_machine.owner_user_id != machine.owner_user_id:
            raise ValueError("machine ownership cannot change through registration")
        previous_policy = self.repository.get_policy(machine.machine_id)
        self._preserve_shared_reserve(policy, previous_policy)
        self._preserve_full_cpu_override(policy, previous_policy)
        if previous_machine is not None:
            self._validate_shared_capacity_change(previous_machine, policy, previous_policy)
            if previous_policy and previous_policy.owner_mode != MachineMode.OPEN and policy.owner_mode == MachineMode.OPEN:
                self._require_machine_open_readiness(machine.machine_id, policy)
        existing_limit = previous_policy.member_execution_limit if previous_policy else None
        if policy.member_execution_limit is not None and policy.member_execution_limit != existing_limit:
            raise ValueError('conditional admission scope requires its dedicated authorization workflow')
        # Registration is also an owner-facing update route. Validate BEFORE the
        # first write, and preserve an existing restriction when older callers omit it.
        policy.member_execution_limit = existing_limit
        self.repository.put_machine(machine)
        self.repository.put_policy(policy)
        self._event("machine.registered", actor_id, "machine", machine.machine_id)
        return machine

    def update_machine(self, machine: MachineState, *, actor_id: str) -> MachineState:
        if self.repository.get_machine(machine.machine_id) is None:
            raise KeyError(f"machine not found: {machine.machine_id}")
        self.repository.put_machine(machine)
        self._event("machine.heartbeat", actor_id, "machine", machine.machine_id)
        return machine

    def record_heartbeat(
        self,
        heartbeat: MachineHeartbeat,
        *,
        actor_id: str,
        update_runtime_status: bool = True,
    ) -> MachineState:
        # Only the machine-token-authenticated API route produces this source.
        # A node's self-reported metrics.source cannot select the evidence path.
        from .connection_health import fresh

        outbound = None
        if update_runtime_status and actor_id == f"machine-agent:{heartbeat.machine_id}":
            received_at = datetime.now(timezone.utc)
            outbound = ChannelObservation(
                observed_at=received_at, transport_state=TransportState.CONNECTED,
                supervisor_at=received_at, metric_at=heartbeat.metrics.observed_at,
                healthy=heartbeat.metrics.available and fresh(heartbeat.metrics.observed_at, received_at),
            )
        try:
            result = self.record_machine_observation(
                heartbeat, actor_id=actor_id, update_runtime_status=update_runtime_status,
                outbound_observation=outbound,
            )
            machine = result.machine
        except StaleMachineObservationError:
            if outbound is None:
                raise
            # Authentication and runtime identity passed; older metrics are not
            # imported, but successful independent HTTP receipt is still a fact.
            machine = self.repository.get_machine(heartbeat.machine_id)
            if machine is None:
                raise
        if outbound is not None:
            previous = self.repository.get_machine_operational_status(heartbeat.machine_id)
            self.repository.put_machine_channel_observation(heartbeat.machine_id, "outbound", outbound)
            current = self.repository.get_machine_operational_status(heartbeat.machine_id)
            prior_outbound = previous.connection_evidence.get("outbound") if previous else None
            if current is not None and (prior_outbound is None or prior_outbound.observed_at != outbound.observed_at):
                self._after_operational_status_update(previous, current, actor_id=actor_id)
        return machine

    def record_machine_observation(
        self,
        heartbeat: MachineHeartbeat,
        *,
        actor_id: str,
        operational_status: MachineOperationalStatus | None = None,
        update_runtime_status: bool = True,
        outbound_observation: ChannelObservation | None = None,
    ) -> MachineObservationResult:
        """Validate, derive, and persist one complete observation aggregate."""

        previous_machine = self.repository.get_machine(heartbeat.machine_id)
        if previous_machine is None:
            raise KeyError(f"machine not found: {heartbeat.machine_id}")
        previous_status = self.repository.get_machine_operational_status(heartbeat.machine_id)
        incoming_at = heartbeat.metrics.observed_at
        previous_at = previous_machine.metrics.observed_at
        incoming_at = incoming_at if incoming_at.tzinfo else incoming_at.replace(tzinfo=timezone.utc)
        previous_at = previous_at if previous_at.tzinfo else previous_at.replace(tzinfo=timezone.utc)
        if incoming_at < previous_at:
            if heartbeat.runtime_version:
                self._attest_machine_runtime(previous_machine.model_copy(deep=True), heartbeat.runtime_version,
                                             actor_id=actor_id, emit_event=False)
            raise StaleMachineObservationError(f"stale machine observation rejected for {heartbeat.machine_id}")
        if operational_status is None and update_runtime_status:
            observed_at = heartbeat.metrics.observed_at
            successes = (previous_status.consecutive_successes if previous_status else 0) + 1
            operational_status = MachineOperationalStatus(
                machine_id=heartbeat.machine_id,
                transport_state=(
                    previous_status.transport_state if previous_status else TransportState.UNKNOWN
                ),
                supervisor_state=SupervisorState.ONLINE,
                telemetry_state=TelemetryState.LIVE,
                last_checked_at=observed_at,
                last_supervisor_heartbeat_at=observed_at,
                last_metric_at=observed_at,
                telemetry_source=heartbeat.metrics.source,
                consecutive_successes=successes,
                consecutive_failures=0,
                heartbeat_phase=(
                    HeartbeatPhase.HEALTHY
                    if previous_status is None
                    or previous_status.heartbeat_phase == HeartbeatPhase.HEALTHY
                    or previous_status.consecutive_successes >= 1
                    else HeartbeatPhase.DELAYED
                ),
                supervisor_reported_concurrent_units=(
                    heartbeat.supervisor_reported_concurrent_units
                    if heartbeat.supervisor_reported_concurrent_units is not None
                    else previous_status.supervisor_reported_concurrent_units
                    if previous_status else None
                ),
            )

        if outbound_observation is not None and operational_status is not None:
            operational_status.connection_evidence = {"outbound": outbound_observation}
            operational_status.last_checked_at = outbound_observation.observed_at

        result = self.machine_observations.prepare(
            heartbeat,
            status=operational_status,
        )
        if result.status is not None and not result.status.observation_consistent:
            self._record_observation_rejection(
                heartbeat.machine_id,
                result.status.observation_issues,
                actor_id=actor_id,
            )
            raise ValueError(
                "inconsistent machine observation rejected: "
                + "; ".join(result.status.observation_issues)
            )
        previous_runtime = previous_machine.runtime_version
        if heartbeat.runtime_version:
            self._attest_machine_runtime(
                result.machine,
                heartbeat.runtime_version,
                actor_id=actor_id,
                emit_event=False,
            )
        if not self.repository.put_machine_observation(
            result.machine,
            result.status,
            result.raw_sample,
        ):
            raise StaleMachineObservationError(
                f"stale machine observation rejected for {heartbeat.machine_id}: "
                f"{heartbeat.metrics.observed_at.isoformat()}"
            )
        if heartbeat.runtime_version and previous_runtime != heartbeat.runtime_version:
            self._event(
                "machine.runtime_attested",
                actor_id,
                "machine",
                heartbeat.machine_id,
                previous_runtime_version=previous_runtime,
                runtime_version=heartbeat.runtime_version,
            )

        metrics = result.machine.metrics
        usage_by_unit = {
            usage.work_unit_id: usage for usage in metrics.attempt_resource_usage
        }
        reported_running = set(heartbeat.running_work_unit_ids)
        if usage_by_unit or reported_running:
            active_statuses = {
                JobStatus.QUEUED,
                JobStatus.RUNNING,
                JobStatus.FAILED_RETRIABLE,
            }
            for active_job in self.repository.list_operational_jobs(
                statuses=active_statuses,
                machine_id=result.machine.machine_id,
                limit=1000,
            ):
                relevant = {
                    unit.work_unit_id: usage_by_unit[unit.work_unit_id]
                    for unit in active_job.work_units
                    if unit.work_unit_id in usage_by_unit
                    and unit.assigned_machine_id == result.machine.machine_id
                    and unit.attempts
                    and not any(a.state == "abandoned" or a.abandonment is not None for a in unit.attempts)
                    and unit.attempts[-1].state in {
                        "assigned", "submitting", "running", "reconcile_pending", "uncertain", "collecting"
                    }
                }
                if not relevant:
                    relevant = {}
                running_units = {
                    unit.work_unit_id
                    for unit in active_job.work_units
                    if unit.work_unit_id in reported_running
                    and unit.assigned_machine_id == result.machine.machine_id
                    and unit.attempts
                    and not any(a.state == "abandoned" or a.abandonment is not None for a in unit.attempts)
                    and unit.attempts[-1].state in {
                        "assigned", "submitting", "reconcile_pending", "uncertain", "running"
                    }
                }
                if not relevant and not running_units:
                    continue

                # Unit-only telemetry cannot distinguish a discarded remote
                # process from its successor. Capture the current binding too,
                # so a concurrent reassignment cannot consume this observation.
                observed_attempt_ids = {
                    unit.work_unit_id: unit.attempts[-1].attempt_id
                    for unit in active_job.work_units
                    if unit.work_unit_id in relevant or unit.work_unit_id in running_units
                }

                newly_running_attempts: list[str] = []
                running_confirmed_at = datetime.now(timezone.utc)

                def update_attempt_peaks(current: JobEnvelope) -> None:
                    newly_running_attempts.clear()
                    for current_unit in current.work_units:
                        usage = relevant.get(current_unit.work_unit_id)
                        if not current_unit.attempts:
                            continue
                        attempt = current_unit.attempts[-1]
                        if (attempt.attempt_id != observed_attempt_ids.get(current_unit.work_unit_id)
                                or current_unit.assigned_machine_id != result.machine.machine_id
                                or attempt.machine_id != result.machine.machine_id
                                or any(a.state == "abandoned" or a.abandonment is not None
                                       for a in current_unit.attempts)
                                or attempt.state not in {
                                    "assigned", "submitting", "running", "reconcile_pending", "uncertain", "collecting"
                                }):
                            continue
                        if usage is not None:
                            attempt.peak_memory_mb = max(
                                attempt.peak_memory_mb or 0,
                                usage.peak_memory_mb,
                            )
                            attempt.peak_disk_mb = max(
                                attempt.peak_disk_mb or 0,
                                (usage.output_bytes + 1024**2 - 1) // 1024**2,
                            )
                        if (
                            current_unit.work_unit_id in running_units
                            and attempt.state in {
                                "assigned", "submitting", "reconcile_pending", "uncertain"
                            }
                        ):
                            attempt.state = "running"
                            attempt.started_at = attempt.started_at or running_confirmed_at
                            attempt.last_observed_at = running_confirmed_at
                            attempt.failure_reason = None
                            attempt.failure_class = None
                            current_unit.status = WorkUnitStatus.RUNNING
                            current_unit.failure_reason = None
                            current.status = JobStatus.RUNNING
                            newly_running_attempts.append(attempt.attempt_id)

                self.repository.mutate_job(
                    active_job.job_id,
                    update_attempt_peaks,
                    hydrate_blobs=False,
                )
                for attempt_id in newly_running_attempts:
                    self._event(
                        "attempt.running_confirmed_by_heartbeat",
                        actor_id,
                        "attempt",
                        attempt_id,
                        job_id=active_job.job_id,
                        machine_id=result.machine.machine_id,
                    )

        recorded_at = result.observation.observed_at
        minute = recorded_at.replace(second=0, microsecond=0)
        raw_for_minute = self.repository.list_metric_samples(
            result.machine.machine_id,
            sample_kind="raw",
            since=minute,
            limit=1000,
        )
        minute_metrics = self._aggregate_metrics([sample.metrics for sample in raw_for_minute])
        self.repository.put_metric_sample(MetricSample(
            sample_id=f"{result.machine.machine_id}:minute:{minute.isoformat()}",
            machine_id=result.machine.machine_id,
            sample_kind="minute",
            metrics=minute_metrics,
            recorded_at=minute,
        ))
        self.repository.purge_metric_samples(
            raw_before=recorded_at - timedelta(hours=6),
            minute_before=recorded_at - timedelta(days=7),
        )
        if result.status is not None:
            self._after_operational_status_update(
                previous_status,
                result.status,
                actor_id=actor_id,
            )
        return result

    def _record_observation_rejection(
        self,
        machine_id: str,
        issues: list[str],
        *,
        actor_id: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        message = "; ".join(issues) or "machine observation evidence is inconsistent"
        alert_id = f"machine:{machine_id}:observation_consistency"
        alert = self.repository.get_alert(alert_id)
        if alert is None:
            alert = AlertRecord(
                alert_id=alert_id,
                severity=AlertSeverity.CRITICAL,
                subject_type="machine",
                subject_id=machine_id,
                kind="observation_consistency",
                message=message,
                reason="incoming observation rejected; last consistent state retained",
                first_seen_at=now,
                last_seen_at=now,
            )
        else:
            alert.status = AlertStatus.ACTIVE
            alert.severity = AlertSeverity.CRITICAL
            alert.message = message
            alert.reason = "incoming observation rejected; last consistent state retained"
            alert.last_seen_at = now
            alert.resolved_at = None
            alert.occurrence_count += 1
        self.repository.put_alert(alert)
        self._event(
            "machine.observation_rejected",
            actor_id,
            "machine",
            machine_id,
            issues=issues,
        )

    def _attest_machine_runtime(
        self,
        machine: MachineState,
        runtime_version: str,
        *,
        actor_id: str,
        emit_event: bool = True,
    ) -> None:
        config = self.repository.get_machine_execution_config(machine.machine_id)
        expected = config.runtime_version if config is not None else None
        if not expected or runtime_version != expected:
            raise ValueError(
                f"machine {machine.machine_id} reported runtime {runtime_version!r}; "
                f"expected configured runtime {expected!r}"
            )
        if not self.runtime_policy.accepts_worker_runtime(runtime_version):
            raise ValueError(
                f"machine {machine.machine_id} reported unsealed runtime {runtime_version!r}"
            )
        if machine.runtime_version != runtime_version:
            previous = machine.runtime_version
            machine.runtime_version = runtime_version
            if emit_event:
                self._event(
                    "machine.runtime_attested",
                    actor_id,
                    "machine",
                    machine.machine_id,
                    previous_runtime_version=previous,
                    runtime_version=runtime_version,
                )

    def record_runtime_attestation(
        self,
        machine_id: str,
        runtime_version: str,
        *,
        actor_id: str,
    ) -> MachineState:
        machine = self.repository.get_machine(machine_id)
        if machine is None:
            raise KeyError(f"machine not found: {machine_id}")
        self._attest_machine_runtime(machine, runtime_version, actor_id=actor_id)
        self.repository.put_machine(machine)
        return machine

    def preview_pressure_override(
        self,
        machine_id: str,
        *,
        reason: str,
        ttl_minutes: int = 30,
        requested_concurrent_units: int | None = None,
        actor_id: str,
    ) -> PressureOverrideTicket:
        reason = reason.strip()
        if not reason:
            raise ValueError("pressure override reason is required")
        machine = self.repository.get_machine(machine_id)
        status = self.repository.get_machine_operational_status(machine_id)
        if machine is None:
            raise KeyError(f"machine not found: {machine_id}")
        if (
            status is None
            or status.supervisor_state != SupervisorState.ONLINE
            or status.telemetry_state != TelemetryState.LIVE
        ):
            raise ValueError("pressure override requires a live supervisor and telemetry")
        policy = self.repository.get_policy(machine_id)
        config = self.repository.get_machine_execution_config(machine_id)
        if policy is None or config is None:
            raise ValueError("machine capacity configuration is incomplete")
        hard_cap = min(policy.max_concurrent_units, config.max_concurrent_units)
        requested_cap = hard_cap if requested_concurrent_units is None else requested_concurrent_units
        if requested_cap < 1 or requested_cap > hard_cap:
            raise ValueError(f"pressure override must be between 1 and validated hard cap {hard_cap}")
        pressure_settings = self.repository.get_feature_settings().pressure_policy
        if ttl_minutes > pressure_settings.max_override_minutes:
            raise ValueError(
                f"pressure override exceeds configured maximum of "
                f"{pressure_settings.max_override_minutes} minutes"
            )
        now = datetime.now(timezone.utc)
        until = now + timedelta(minutes=max(ttl_minutes, 1))
        canonical = (
            f"{machine_id}|{reason}|{requested_cap}|{until.isoformat()}|"
            f"{machine.last_heartbeat_at.isoformat()}"
        )
        confirmation_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        ticket = PressureOverrideTicket(
            machine_id=machine_id,
            issued_by=actor_id,
            reason=reason,
            confirmation_hash=confirmation_hash,
            requested_until=until,
            requested_concurrent_units=requested_cap,
            expires_at=min(until, now + timedelta(minutes=5)),
        )
        self.repository.put_pressure_override_ticket(ticket)
        return ticket

    @pressure_confirmation
    def confirm_pressure_override(
        self,
        machine_id: str,
        *,
        ticket_id: str,
        confirmation_hash: str,
        actor_id: str,
    ) -> MachineOperationalStatus:
        ticket = self.repository.get_pressure_override_ticket(ticket_id)
        now = datetime.now(timezone.utc)
        if (
            ticket is None
            or ticket.machine_id != machine_id
            or ticket.issued_by != actor_id
            or ticket.confirmation_hash != confirmation_hash
            or ticket.expires_at <= now
        ):
            raise ValueError("pressure override preview is invalid or expired")
        status = self.repository.get_machine_operational_status(machine_id)
        if (
            status is None
            or status.supervisor_state != SupervisorState.ONLINE
            or status.telemetry_state != TelemetryState.LIVE
        ):
            raise ValueError("pressure override requires a live supervisor and telemetry")
        policy = self.repository.get_policy(machine_id)
        config = self.repository.get_machine_execution_config(machine_id)
        if policy is None or config is None:
            raise ValueError("machine capacity configuration is incomplete")
        static_cap = min(policy.max_concurrent_units, config.max_concurrent_units)
        requested_cap = ticket.requested_concurrent_units or static_cap
        if requested_cap > static_cap:
            raise ValueError("pressure override exceeds the current validated hard cap")
        profile_cap = config.profile_concurrency_limits.get("workbench-comsol-scan-v1")
        effective_override = min(
            requested_cap,
            profile_cap if profile_cap is not None else static_cap,
        )
        status.pressure_state = PressureState.OVERRIDE
        status.effective_comsol_concurrency = effective_override
        status.capacity_reason = "active administrator pressure override"
        status.capacity_decision_at = now
        status.pressure_override_until = ticket.requested_until
        status.pressure_override_reason = ticket.reason
        status.pressure_override_actor = actor_id
        status.pressure_override_hash = ticket.confirmation_hash
        status.pressure_override_concurrency = requested_cap
        self.repository.put_machine_operational_status(status)
        self._event(
            "machine.pressure_override_confirmed",
            actor_id,
            "machine",
            machine_id,
            ticket_id=ticket_id,
            expires_at=ticket.requested_until.isoformat(),
            requested_concurrent_units=requested_cap,
            effective_concurrent_units=effective_override,
            reason=ticket.reason,
        )
        self.repository.delete_pressure_override_ticket(ticket_id)
        return status

    def preview_admin_operation(
        self,
        action: AdminOperation,
        *,
        job_id: str,
        work_unit_id: str | None = None,
        reason: str = "",
        actor_id: str,
    ) -> AdminOperationTicket:
        job = self.repository.get_job(job_id)
        if job is None:
            raise KeyError(f"job not found: {job_id}")
        reason = reason.strip()
        if action in {AdminOperation.CANCEL_JOB, AdminOperation.CANCEL_UNIT} and not reason:
            raise ValueError("a cancellation reason is required")
        unit = None
        if action in {AdminOperation.CANCEL_UNIT, AdminOperation.RETRY_UNIT}:
            if not work_unit_id:
                raise ValueError("work_unit_id is required for a unit operation")
            unit = next((item for item in job.work_units if item.work_unit_id == work_unit_id), None)
            if unit is None:
                raise KeyError(f"work unit not found: {work_unit_id}")
        if action == AdminOperation.CANCEL_JOB and job.status in {
            JobStatus.COMPLETED, JobStatus.CANCELLED, JobStatus.FAILED_TERMINAL,
        }:
            raise ValueError(f"job cannot be cancelled from {job.status.value}")
        if action == AdminOperation.RETRY_JOB and job.status != JobStatus.FAILED_RETRIABLE:
            raise ValueError("only a retriable failed job can be retried")
        if action == AdminOperation.CANCEL_UNIT and unit.status not in {
            WorkUnitStatus.QUEUED, WorkUnitStatus.ASSIGNED, WorkUnitStatus.RUNNING,
            WorkUnitStatus.COLLECTING, WorkUnitStatus.FAILED_RETRIABLE,
        }:
            raise ValueError(f"work unit cannot be cancelled from {unit.status.value}")
        if action == AdminOperation.RETRY_UNIT and not (
            unit.status in {WorkUnitStatus.FAILED_RETRIABLE, WorkUnitStatus.CANCELLED}
            or self._recoverable_prelaunch_terminal(unit)
            or self._recoverable_storage_terminal(unit, job.job_id)
        ):
            raise ValueError("only a retriable, administrator-cancelled, or recoverable pre-launch work unit can be retried")
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        impact = {
            "job_status": job.status.value,
            "job_revision": job.revision,
            "affected_units": (
                1 if unit is not None else len([
                    item for item in job.work_units
                    if item.status not in {WorkUnitStatus.COMPLETED, WorkUnitStatus.CANCELLED}
                ])
            ),
            "unit_status": unit.status.value if unit is not None else None,
        }
        canonical = "|".join([
            action.value, job_id, work_unit_id or "", reason,
            str(job.revision), expires_at.isoformat(),
        ])
        ticket = AdminOperationTicket(
            action=action,
            job_id=job_id,
            work_unit_id=work_unit_id,
            reason=reason,
            expected_revision=job.revision,
            impact=impact,
            confirmation_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            issued_by=actor_id,
            expires_at=expires_at,
        )
        self.repository.put_admin_operation_ticket(ticket)
        self._event(
            "admin_operation.previewed", actor_id, "job", job_id,
            ticket_id=ticket.ticket_id, action=action.value,
            work_unit_id=work_unit_id, reason=reason,
        )
        return ticket

    @admin_confirmation
    def confirm_admin_operation(
        self,
        *,
        ticket_id: str,
        confirmation_hash: str,
        actor_id: str,
    ) -> JobEnvelope:
        ticket = self.repository.get_admin_operation_ticket(ticket_id)
        now = datetime.now(timezone.utc)
        if ticket is None or ticket.confirmation_hash != confirmation_hash or ticket.expires_at <= now:
            raise ValueError("administrator operation preview is invalid or expired")
        job = self.repository.get_job(ticket.job_id)
        if job is None:
            raise KeyError(f"job not found: {ticket.job_id}")
        if job.revision != ticket.expected_revision:
            raise ValueError("job changed after preview; create a new preview")
        if ticket.action == AdminOperation.CANCEL_JOB:
            result = self.cancel(ticket.job_id, actor_id=actor_id, reason=ticket.reason)
        elif ticket.action == AdminOperation.RETRY_JOB:
            result = self.retry(ticket.job_id, actor_id=actor_id)
        elif ticket.action == AdminOperation.CANCEL_UNIT:
            result = self.cancel_unit(
                ticket.job_id, ticket.work_unit_id,
                actor_id=actor_id, reason=ticket.reason,
            )
        elif ticket.action == AdminOperation.RETRY_UNIT:
            result = self.retry_unit(
                ticket.job_id,
                ticket.work_unit_id,
                actor_id=actor_id,
                allow_cancelled=True,
            )
        else:
            raise ValueError(f"unsupported administrator operation: {ticket.action.value}")
        self.repository.delete_admin_operation_ticket(ticket_id)
        self._event(
            "admin_operation.confirmed", actor_id, "job", ticket.job_id,
            ticket_id=ticket_id, action=ticket.action.value,
            work_unit_id=ticket.work_unit_id, resulting_status=result.status.value,
        )
        return result

    @staticmethod
    def _aggregate_metrics(samples: list[MachineMetrics]) -> MachineMetrics:
        if not samples:
            raise ValueError("cannot aggregate an empty metric window")

        def mean(name: str) -> float:
            return sum(float(getattr(sample, name)) for sample in samples) / len(samples)

        def machine_optional_mean(name: str) -> float | None:
            values = [
                float(value)
                for sample in samples
                if (value := getattr(sample, name)) is not None
            ]
            return sum(values) / len(values) if values else None

        gpu_by_index: dict[int, list[GpuMetric]] = {}
        for sample in samples:
            for gpu in sample.gpu:
                gpu_by_index.setdefault(gpu.index, []).append(gpu)

        def optional_mean(items: list[GpuMetric], name: str) -> float | None:
            values = [float(value) for item in items if (value := getattr(item, name)) is not None]
            return sum(values) / len(values) if values else None

        gpu = [
            GpuMetric(
                index=index,
                name=items[-1].name,
                utilization_percent=optional_mean(items, "utilization_percent"),
                utilization_average_percent=optional_mean(items, "utilization_average_percent"),
                utilization_5m_average_percent=optional_mean(
                    items, "utilization_5m_average_percent"
                ),
                utilization_peak_percent=max(
                    (
                        float(item.utilization_peak_percent)
                        for item in items
                        if item.utilization_peak_percent is not None
                    ),
                    default=None,
                ),
                utilization_p95_percent=optional_mean(items, "utilization_p95_percent"),
                busy_duty_cycle_percent=optional_mean(items, "busy_duty_cycle_percent"),
                sample_count=max((item.sample_count for item in items), default=0),
                memory_used_mb=(round(value) if (value := optional_mean(items, "memory_used_mb")) is not None else None),
                memory_peak_mb=max(
                    (item.memory_peak_mb for item in items if item.memory_peak_mb is not None),
                    default=None,
                ),
                memory_total_mb=(round(value) if (value := optional_mean(items, "memory_total_mb")) is not None else None),
                temperature_c=optional_mean(items, "temperature_c"),
                available=all(item.available for item in items),
                sampling_quality=(
                    items[-1].sampling_quality
                    if len({item.sampling_quality for item in items}) == 1
                    else "degraded"
                ),
            )
            for index, items in sorted(gpu_by_index.items())
        ]
        latest = samples[-1]
        sources = {sample.source for sample in samples}
        external_samples = [sample.external_load for sample in samples]
        external_process_count = max(
            (sample.external_load.external_process_count for sample in samples),
            default=0,
        )
        external_process_set_hash = latest.external_load.process_set_hash
        external_load = ExternalLoadSnapshot(
            external_process_count=external_process_count,
            external_cpu_percent=machine_optional_mean("external_cpu_percent") or 0.0,
            external_memory_mb=round(
                sum(item.external_memory_mb for item in external_samples) / len(external_samples)
            ),
            external_gpu_utilization_percent=(
                sum(item.external_gpu_utilization_percent for item in external_samples)
                / len(external_samples)
            ),
            process_set_hash=external_process_set_hash,
            attribution_quality=(
                latest.external_load.attribution_quality
                if len({item.attribution_quality for item in external_samples}) == 1
                else "degraded"
            ),
            unattributed_cpu_percent=(
                sum(item.unattributed_cpu_percent for item in external_samples)
                / len(external_samples)
            ),
            unattributed_memory_mb=round(
                sum(item.unattributed_memory_mb for item in external_samples)
                / len(external_samples)
            ),
            reason_codes=sorted({code for item in external_samples for code in item.reason_codes}),
            observed_at=latest.external_load.observed_at,
        )
        return MachineMetrics(
            cpu_total_percent=mean("cpu_total_percent"),
            cpu_current_percent=latest.cpu_current_percent,
            cpu_average_percent=machine_optional_mean("cpu_average_percent"),
            cpu_peak_percent=max(
                (
                    float(sample.cpu_peak_percent)
                    for sample in samples
                    if sample.cpu_peak_percent is not None
                ),
                default=None,
            ),
            network_cpu_percent=machine_optional_mean("network_cpu_percent"),
            external_cpu_percent=machine_optional_mean("external_cpu_percent"),
            cpu_attribution_quality=(
                latest.cpu_attribution_quality
                if len({sample.cpu_attribution_quality for sample in samples}) == 1
                else "degraded"
            ),
            keyboard_idle_s=round(mean("keyboard_idle_s")),
            non_pool_cpu_percent=mean("non_pool_cpu_percent"),
            memory_used_mb=round(mean("memory_used_mb")),
            total_memory_mb=round(mean("total_memory_mb")),
            available_memory_mb=round(mean("available_memory_mb")),
            disk_used_mb=round(mean("disk_used_mb")),
            total_disk_mb=round(mean("total_disk_mb")),
            free_disk_mb=round(mean("free_disk_mb")),
            running_units=round(mean("running_units")),
            gpu=gpu,
            external_load=external_load,
            external_process_set_hash=external_process_set_hash,
            external_process_count=external_process_count,
            external_comsol_process_set_hash=external_process_set_hash,
            external_comsol_process_count=external_process_count,
            available=all(sample.available for sample in samples),
            unavailable_reasons=sorted({reason for sample in samples for reason in sample.unavailable_reasons}),
            source=next(iter(sources)) if len(sources) == 1 else "mixed",
            observed_at=latest.observed_at.replace(second=0, microsecond=0),
        )

    def update_operational_status(
        self,
        status: MachineOperationalStatus,
        *,
        actor_id: str,
    ) -> MachineOperationalStatus:
        machine = self.repository.get_machine(status.machine_id)
        if machine is None:
            raise KeyError(f"machine not found: {status.machine_id}")
        previous = self.repository.get_machine_operational_status(status.machine_id)
        status = finalize_operational_status(
            status,
            machine=machine,
            policy=self.repository.get_policy(status.machine_id),
            config=self.repository.get_machine_execution_config(status.machine_id),
            previous=previous,
            pressure_settings=self.repository.get_feature_settings().pressure_policy,
        )
        if not self.repository.put_machine_operational_status_if_newer(status):
            return previous or status
        self._after_operational_status_update(previous, status, actor_id=actor_id)
        return status

    def _after_operational_status_update(
        self,
        previous: MachineOperationalStatus | None,
        status: MachineOperationalStatus,
        *,
        actor_id: str,
    ) -> None:
        status = self.repository.get_machine_operational_status(status.machine_id) or status
        self._sync_machine_alerts(status)
        previous_state = (
            previous.transport_state.value,
            previous.supervisor_state.value,
            previous.telemetry_state.value,
        ) if previous else None
        current_state = (
            status.transport_state.value,
            status.supervisor_state.value,
            status.telemetry_state.value,
        )
        if previous_state != current_state:
            self._event(
                "machine.runtime_status_changed",
                actor_id,
                "machine",
                status.machine_id,
                previous=previous_state,
                current=current_state,
                detail=status.detail,
            )
        # ``candidate`` is a live hysteresis observation, not an enforced
        # capacity transition. Short CPU/GPU bursts can toggle it every poll;
        # persisting each toggle floods the audit stream and obscures actual
        # dispatch changes. Keep the state in machine telemetry, but audit
        # only enforced pressure states or a real capacity change.
        enforced_pressure_states = {
            PressureState.PRESSURED,
            PressureState.TELEMETRY_STALE,
            PressureState.OVERRIDE,
        }
        previous_pressure_state = (
            previous.pressure_state
            if previous is not None and previous.pressure_state in enforced_pressure_states
            else PressureState.NORMAL
        )
        current_pressure_state = (
            status.pressure_state
            if status.pressure_state in enforced_pressure_states
            else PressureState.NORMAL
        )
        if previous is None or (
            previous_pressure_state != current_pressure_state
            or previous.effective_comsol_concurrency != status.effective_comsol_concurrency
        ):
            self._event(
                "machine.pressure_changed",
                actor_id,
                "machine",
                status.machine_id,
                pressure_state=status.pressure_state.value,
                effective_comsol_concurrency=status.effective_comsol_concurrency,
                reason=status.capacity_reason,
            )
        if not status.observation_consistent and (
            previous is None
            or previous.observation_consistent
            or previous.observation_issues != status.observation_issues
        ):
            self._event(
                "machine.observation_inconsistent",
                actor_id,
                "machine",
                status.machine_id,
                issues=status.observation_issues,
            )

    def _sync_machine_alerts(self, status: MachineOperationalStatus) -> None:
        now = datetime.now(timezone.utc)
        conditions = {
            "transport": (
                status.transport_state == TransportState.DISCONNECTED,
                AlertSeverity.WARNING,
                "SSH transport is disconnected; host liveness is evaluated independently",
            ),
            "executor": (
                status.supervisor_state != SupervisorState.ONLINE
                and status.heartbeat_phase in {HeartbeatPhase.STALE, HeartbeatPhase.OFFLINE},
                AlertSeverity.CRITICAL,
                f"executor heartbeat is {status.heartbeat_phase.value}",
            ),
            "telemetry": (
                status.telemetry_state != TelemetryState.LIVE
                and status.heartbeat_phase in {HeartbeatPhase.STALE, HeartbeatPhase.OFFLINE},
                AlertSeverity.WARNING,
                f"telemetry is {status.heartbeat_phase.value}",
            ),
            "pressure": (
                status.pressure_state in {PressureState.PRESSURED, PressureState.TELEMETRY_STALE},
                AlertSeverity.WARNING,
                status.capacity_reason or status.pressure_state.value,
            ),
            "capacity_drift": (
                status.capacity_drift,
                AlertSeverity.WARNING,
                status.capacity_drift_reason or "Control Plane and Supervisor capacities differ",
            ),
            "observation_consistency": (
                not status.observation_consistent,
                AlertSeverity.CRITICAL,
                "; ".join(status.observation_issues) or "machine observation evidence is inconsistent",
            ),
        }
        for kind, (active, severity, message) in conditions.items():
            alert_id = f"machine:{status.machine_id}:{kind}"
            existing = self.repository.get_alert(alert_id)
            if active:
                if existing is None:
                    existing = AlertRecord(
                        alert_id=alert_id,
                        severity=severity,
                        subject_type="machine",
                        subject_id=status.machine_id,
                        kind=kind,
                        message=message,
                        reason=status.detail or status.capacity_reason,
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                else:
                    existing.severity = severity
                    existing.message = message
                    existing.reason = status.detail or status.capacity_reason
                    existing.last_seen_at = now
                    existing.occurrence_count += 1
                    if existing.status == AlertStatus.RESOLVED:
                        existing.status = AlertStatus.ACTIVE
                        existing.resolved_at = None
                self.repository.put_alert(existing)
            elif existing is not None and existing.status != AlertStatus.RESOLVED:
                existing.status = AlertStatus.RESOLVED
                existing.resolved_at = now
                existing.last_seen_at = now
                self.repository.put_alert(existing)

    def preview_demo_cleanup(self):
        return self.repository.preview_demo_cleanup()

    def confirm_demo_cleanup(self, confirmation_hash: str, *, actor_id: str):
        preview = self.repository.confirm_demo_cleanup(confirmation_hash)
        self._event(
            "demo_data.cleaned",
            actor_id,
            "dataset",
            "formal",
            counts=preview.counts,
            confirmation_hash=preview.confirmation_hash,
        )
        return preview

    @staticmethod
    def _preserve_shared_reserve(policy: MachinePolicy, existing: MachinePolicy | None) -> None:
        """Old clients cannot erase shared-host classification by omitting fields."""
        if existing is None:
            return
        for name in ("shared_machine", "cpu_reserve_percent", "memory_peak_margin_percent"):
            if name not in policy.model_fields_set:
                setattr(policy, name, getattr(existing, name))
        if existing.shared_machine and not policy.shared_machine:
            raise ValueError("shared machine reserve cannot be removed through ordinary policy edits")

    @staticmethod
    def _preserve_full_cpu_override(
        policy: MachinePolicy, existing: MachinePolicy | None, *, authorized: bool = False,
    ) -> None:
        existing_override = existing.full_cpu_override if existing else None
        if "full_cpu_override" not in policy.model_fields_set:
            policy.full_cpu_override = existing_override
        elif policy.full_cpu_override != existing_override and not authorized:
            raise ValueError("full CPU override requires its dedicated authorization workflow")
        if (policy.full_cpu_override is not None
                and (policy.member_execution_limit is not None
                     or (existing is not None and existing.member_execution_limit is not None))):
            raise ValueError("full CPU override is unavailable for invitation-limited machines")

    @atomic_metadata
    def update_policy(
        self, policy: MachinePolicy, *, actor_id: str,
        full_cpu_override_authorized: bool = False,
        admin_override_authorized: bool = False,
        expected_policy_sha256: str | None = None,
        expected_policy_payload_sha256: str | None = None,
    ) -> MachinePolicy:
        machine = self.repository.get_machine(policy.machine_id)
        if machine is None:
            raise KeyError(f"machine not found: {policy.machine_id}")
        if machine.owner_user_id != policy.owner_user_id:
            raise ValueError("machine policy owner differs from the registered owner")
        existing_policy = self.repository.get_policy(policy.machine_id)
        if expected_policy_payload_sha256 is not None:
            _validate_policy_payload_sha256(expected_policy_payload_sha256)
            revision = self.repository.get_policy_revision(policy.machine_id)
            if revision is None or revision['revision_hash'] != expected_policy_payload_sha256:
                raise PolicyRevisionConflict('machine policy changed; read the same machine again')
        if (not admin_override_authorized and policy.admin_mode_override != (
                existing_policy.admin_mode_override if existing_policy is not None else None)):
            raise PermissionError("only an administrator can change an admin override")
        if existing_policy is not None:
            if not admin_override_authorized:
                for name in ("admin_override_reason", "admin_override_actor", "admin_override_at"):
                    setattr(policy, name, getattr(existing_policy, name))
            if expected_policy_sha256 is None:
                expected_policy_sha256 = sha256_value(existing_policy.model_dump(mode="json"))
        self._preserve_shared_reserve(policy, existing_policy)
        self._preserve_full_cpu_override(
            policy, existing_policy, authorized=full_cpu_override_authorized,
        )
        self._validate_shared_capacity_change(machine, policy, existing_policy)
        if existing_policy and existing_policy.owner_mode != MachineMode.OPEN and policy.owner_mode == MachineMode.OPEN:
            self._require_machine_open_readiness(policy.machine_id, policy)
        existing_limit = existing_policy.member_execution_limit if existing_policy else None
        if policy.member_execution_limit is not None and policy.member_execution_limit != existing_limit:
            raise ValueError('conditional admission scope requires its dedicated authorization workflow')
        # Older UI payloads omit the limit. Omission is not permission to delete it.
        policy.member_execution_limit = existing_limit
        policy.updated_at = datetime.now(timezone.utc)
        write_options = {}
        if full_cpu_override_authorized:
            write_options['full_cpu_override_authorized'] = True
        if admin_override_authorized:
            write_options['admin_override_authorized'] = True
        if expected_policy_sha256 is not None:
            write_options['expected_policy_sha256'] = expected_policy_sha256
        if expected_policy_payload_sha256 is not None:
            write_options['expected_policy_payload_sha256'] = expected_policy_payload_sha256
        self.repository.put_policy(policy, **write_options)
        self._event(
            "machine.policy_updated",
            actor_id,
            "machine",
            policy.machine_id,
            owner_mode=policy.owner_mode.value,
            shared_machine=policy.shared_machine,
            cpu_reserve_percent=policy.cpu_reserve_percent,
            effective_cpu_cap=policy.effective_cpu_cap(machine.total_cpus),
            full_cpu_override=(policy.full_cpu_override.model_dump(mode="json")
                               if policy.full_cpu_override else None),
            memory_peak_margin_percent=policy.memory_peak_margin_percent,
            admin_override=policy.admin_mode_override.value if policy.admin_mode_override else None,
            member_profile_grants={member: sorted(profiles)
                for member, profiles in sorted(policy.member_profile_grants.items())},
            timezone=policy.timezone,
            schedule_restricted=bool(policy.weekly_windows),
            weekly_windows={
                str(day): [window.model_dump(mode="json") for window in windows]
                for day, windows in sorted(policy.weekly_windows.items())
            },
        )
        return policy

    def _require_machine_open_readiness(self, machine_id: str, policy: MachinePolicy) -> None:
        if self.repository.get_member_retirement(machine_id) is not None:
            raise ExecutionCompatibilityError("member_retirement_active", "owner retirement is draining; execution cannot reopen")
        from .admission_governance import trust_first_execution, trust_readiness_blockers
        machine = self.repository.get_machine(machine_id)
        config = self.repository.get_machine_execution_config(machine_id)
        if trust_first_execution(config):
            reasons = trust_readiness_blockers(machine, policy, config,
                self.repository.get_machine_operational_status(machine_id))
            if not config.enabled:
                reasons.append('enabled_execution_configuration_required')
            if reasons:
                raise ExecutionCompatibilityError('machine_readiness_required', ', '.join(reasons))
            return
        blockers: list[str] = []
        if machine is None or machine.runtime_version != self.runtime_policy.stable_runtime_version:
            blockers.append('runtime attestation')
        if config is None or not config.enabled:
            blockers.append('enabled execution configuration')
        elif (config.operational_execution != 'passed' or config.startup_after_reboot != 'passed'
              or config.numeric_equivalence not in {'passed', 'warning'}
              or config.runtime_version != self.runtime_policy.stable_runtime_version):
            blockers.append('preflight and controlled execution acceptance')
        if blockers:
            raise ExecutionCompatibilityError('machine_acceptance_required',
                'machine must remain paused until an administrator completes ' + ', '.join(blockers))

    def _validate_shared_capacity_change(self, machine, policy, existing) -> None:
        if existing is None or not policy.shared_machine:
            return
        if existing.shared_machine and policy.effective_cpu_cap(machine.total_cpus) >= existing.effective_cpu_cap(machine.total_cpus):
            return
        # A new tighter budget cannot honestly apply retroactively to sealed work.
        # Drain first; never kill, resize, or rewrite already-running science.
        if machine.metrics.running_units:
            raise ValueError('drain active work before enabling or tightening a shared machine CPU reserve')
        terminal = {RemoteRunState.COMPLETED, RemoteRunState.FAILED,
                    RemoteRunState.CANCELLED, RemoteRunState.INTERRUPTED}
        if any(run.state not in terminal for run in self.repository.list_remote_runs(machine.machine_id)):
            raise ValueError('drain active work before enabling or tightening a shared machine CPU reserve')
        active = {WorkUnitStatus.ASSIGNED, WorkUnitStatus.RUNNING, WorkUnitStatus.RECONCILE_PENDING}
        if any(unit.assigned_machine_id == machine.machine_id and unit.status in active
               for job in self.repository.list_operational_jobs(statuses={JobStatus.QUEUED, JobStatus.RUNNING})
               for unit in job.work_units):
            raise ValueError('drain active work before enabling or tightening a shared machine CPU reserve')

    @atomic_metadata
    def set_machine_mode(
        self,
        machine_id: str,
        mode: MachineMode,
        *,
        actor_id: str,
        reason: str = "",
    ) -> MachinePolicy:
        policy = self.repository.get_policy(machine_id)
        if policy is None:
            raise KeyError(f"machine policy not found: {machine_id}")
        if mode == MachineMode.OPEN:
            self._require_machine_open_readiness(machine_id, policy)
        policy.owner_mode = mode
        self.repository.put_policy(policy)
        self._event(
            "machine.mode_changed",
            actor_id,
            "machine",
            machine_id,
            mode=mode.value,
            reason=reason,
        )
        return policy





    @atomic_metadata
    def revoke_token(self, token_id: str, *, actor_id: str) -> ApiTokenRecord:
        token = self.repository.get_token(token_id)
        if token is None:
            raise KeyError(f"API token not found: {token_id}")
        if not token.active:
            return token
        token.active = False
        self.repository.put_token(token)
        self._event("api_token.revoked", actor_id, "user", token.user_id, token_id=token_id)
        return token

    @atomic_metadata
    def set_break_glass_pin(self, pin: str, *, actor_id: str) -> BreakGlassConfig:
        if len(pin) < 8 or len(pin) > 128:
            raise ValueError("break-glass PIN must contain 8 to 128 characters")
        salt = os.urandom(16)
        config = BreakGlassConfig(
            salt_hex=salt.hex(),
            digest_hex=hashlib.scrypt(
                pin.encode("utf-8"), salt=salt, n=32768, r=8, p=1,
                maxmem=128 * 1024 * 1024, dklen=32,
            ).hex(),
        )
        self.repository.put_break_glass_config(config)
        self._event("break_glass.pin_rotated", actor_id, "break_glass", "global")
        return config

    def verify_break_glass_pin(self, pin: str) -> bool:
        config = self.repository.get_break_glass_config()
        if config is None or not config.active:
            return False
        candidate = hashlib.scrypt(
            pin.encode("utf-8"),
            salt=bytes.fromhex(config.salt_hex),
            n=config.n,
            r=config.r,
            p=config.p,
            maxmem=128 * 1024 * 1024,
            dklen=len(bytes.fromhex(config.digest_hex)),
        )
        return hmac.compare_digest(candidate.hex(), config.digest_hex)

    def machine_control_fingerprint(
        self,
        machine_id: str,
        action: MachineControlAction,
    ) -> str:
        machine = self.repository.get_machine(machine_id)
        policy = self.repository.get_policy(machine_id)
        config = self.repository.get_machine_execution_config(machine_id)
        status = self.repository.get_machine_operational_status(machine_id)
        if machine is None or policy is None:
            raise KeyError(f"machine control state not found: {machine_id}")
        payload: dict[str, Any] = {"machine_id": machine_id, "action": action.value}
        if action in {
            MachineControlAction.SET_ADMIN_MODE,
            MachineControlAction.CLEAR_ADMIN_MODE,
        }:
            payload["policy"] = {
                "owner_mode": policy.owner_mode.value,
                "admin_mode": policy.admin_mode_override.value if policy.admin_mode_override else None,
            }
        elif action in {
            MachineControlAction.SET_TARGET_CAPACITY,
            MachineControlAction.SET_HARD_CAPACITY,
            MachineControlAction.ACCEPT_HARD_CAPACITY,
        }:
            payload["capacity"] = {
                "policy_cap": policy.max_concurrent_units,
                "config_cap": config.max_concurrent_units if config else None,
                "target": config.target_concurrent_units if config else None,
                "accepted_hard_cap": config.accepted_hard_capacity_units if config else None,
                "pending_acceptance": config.hard_capacity_pending_acceptance if config else None,
                "acceptance_reference": config.hard_capacity_acceptance_reference if config else None,
            }
        else:
            payload["runtime"] = {
                "registered_version": machine.runtime_version,
                "execution_config": config.model_dump(mode="json") if config else None,
            }
        if action in {
            MachineControlAction.GRACEFUL_STOP,
            MachineControlAction.EMERGENCY_STOP_NETWORK,
            MachineControlAction.EMERGENCY_STOP_HOST,
            MachineControlAction.RESTART_SUPERVISOR,
            MachineControlAction.FORCE_RESTART_SUPERVISOR,
        }:
            payload["active_attempts"] = self.repository.list_active_attempt_ids(machine_id)
            payload["reported_running_units"] = machine.metrics.running_units
            payload["process_set_hash"] = status.external_comsol_process_set_hash if status else None
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def runtime_control_fingerprint(self, machine_id: str) -> str:
        """Fingerprint durable state for a runtime promotion or rollback.

        Telemetry is deliberately excluded.  It refreshes continuously and
        cannot change whether an already verified, idle sealed supervisor may
        have its formal runtime version updated.
        """
        machine = self.repository.get_machine(machine_id)
        policy = self.repository.get_policy(machine_id)
        config = self.repository.get_machine_execution_config(machine_id)
        if machine is None or policy is None or config is None:
            raise KeyError(f"runtime control state not found: {machine_id}")
        active_attempts = self.repository.list_active_attempt_ids(machine_id)
        payload = {
            "machine_id": machine_id,
            "registered_runtime": machine.runtime_version,
            "owner_mode": policy.owner_mode.value,
            "admin_mode": policy.admin_mode_override.value if policy.admin_mode_override else None,
            "policy_cap": policy.max_concurrent_units,
            "execution_config": config.model_dump(mode="json"),
            "active_attempts": active_attempts,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _machine_control_reason_required(
        action: MachineControlAction,
        targets: list[MachineControlTarget],
    ) -> bool:
        if action in {
            MachineControlAction.GRACEFUL_STOP,
            MachineControlAction.EMERGENCY_STOP_NETWORK,
            MachineControlAction.EMERGENCY_STOP_HOST,
            MachineControlAction.RESTART_SUPERVISOR,
            MachineControlAction.FORCE_RESTART_SUPERVISOR,
        }:
            return True
        return action == MachineControlAction.SET_ADMIN_MODE and any(
            target.requested_mode in {MachineMode.PAUSED, MachineMode.EMERGENCY_STOP}
            for target in targets
        )

    def preview_machine_control(
        self,
        action: MachineControlAction,
        targets: list[MachineControlTarget],
        *,
        reason: str,
        actor_id: str,
    ) -> MachineControlTicket:
        if not targets or len(targets) > 5:
            raise ValueError("machine control requires between one and five targets")
        machine_ids = [target.machine_id for target in targets]
        if len(set(machine_ids)) != len(machine_ids):
            raise ValueError("machine control targets must be unique")
        reason = reason.strip()
        if self._machine_control_reason_required(action, targets) and not reason:
            raise ValueError("this machine control action requires a reason")
        if action == MachineControlAction.EMERGENCY_STOP_HOST and len(targets) != 1:
            raise ValueError("host-wide COMSOL termination is restricted to one machine")

        expected: dict[str, str] = {}
        impact: dict[str, dict] = {}
        remote_actions = {
            MachineControlAction.SET_TARGET_CAPACITY,
            MachineControlAction.SET_HARD_CAPACITY,
            MachineControlAction.HEALTH_PROBE,
            MachineControlAction.GRACEFUL_STOP,
            MachineControlAction.EMERGENCY_STOP_NETWORK,
            MachineControlAction.EMERGENCY_STOP_HOST,
            MachineControlAction.RESTART_SUPERVISOR,
            MachineControlAction.FORCE_RESTART_SUPERVISOR,
        }
        for target in targets:
            machine = self.repository.get_machine(target.machine_id)
            policy = self.repository.get_policy(target.machine_id)
            config = self.repository.get_machine_execution_config(target.machine_id)
            status = self.repository.get_machine_operational_status(target.machine_id)
            if machine is None or policy is None or config is None:
                raise KeyError(f"machine control configuration not found: {target.machine_id}")
            if target.target_concurrent_units is not None:
                hard_cap = min(policy.max_concurrent_units, config.max_concurrent_units)
                if target.target_concurrent_units > hard_cap:
                    raise ValueError(
                        f"target capacity for {target.machine_id} exceeds validated hard cap {hard_cap}"
                    )
            if action == MachineControlAction.SET_ADMIN_MODE and target.requested_mode is None:
                raise ValueError("set_admin_mode requires requested_mode for every target")
            if action == MachineControlAction.SET_TARGET_CAPACITY and target.target_concurrent_units is None:
                raise ValueError("set_target_capacity requires a target for every machine")
            if action == MachineControlAction.SET_HARD_CAPACITY:
                if target.hard_capacity_units is None:
                    raise ValueError("set_hard_capacity requires a hard capacity for every machine")
                current_hard_cap = min(policy.max_concurrent_units, config.max_concurrent_units)
                if target.hard_capacity_units > current_hard_cap and not reason:
                    raise ValueError("raising hard capacity requires a reason")
            if action == MachineControlAction.ACCEPT_HARD_CAPACITY:
                if not config.hard_capacity_pending_acceptance:
                    raise ValueError(f"{target.machine_id} has no hard capacity awaiting acceptance")
                if not (target.acceptance_reference or "").strip():
                    raise ValueError("capacity acceptance requires an Agent acceptance reference")
            # A supervisor restart is the recovery path for a stale or exited
            # supervisor, so it must not require the very live heartbeat it is
            # intended to restore. Other remote actions still require a live
            # versioned supervisor; restart retains the sealed identity and
            # runtime checks below and is blocked for active work unless the
            # explicit force action is selected.
            restart_action = action in {
                MachineControlAction.RESTART_SUPERVISOR,
                MachineControlAction.FORCE_RESTART_SUPERVISOR,
            }
            if action in remote_actions and (
                status is None
                or (status.supervisor_state != SupervisorState.ONLINE and not restart_action)
                or not config.root_uuid
                or not config.runtime_version
            ):
                raise ValueError(f"{target.machine_id} requires a live versioned supervisor")
            if action == MachineControlAction.RESTART_SUPERVISOR and machine.metrics.running_units:
                raise ValueError(f"{target.machine_id} has active work; use force restart preview")
            if action == MachineControlAction.EMERGENCY_STOP_HOST and (
                status is None
                or status.telemetry_state != TelemetryState.LIVE
                or not status.external_comsol_process_set_hash
            ):
                raise ValueError("host-wide termination requires live telemetry and a process-set hash")
            if (
                action == MachineControlAction.EMERGENCY_STOP_HOST
                and not policy.external_comsol_termination_authorized
            ):
                raise ExecutionCompatibilityError(
                    "host_comsol_termination_not_authorized",
                    "machine owner has disabled external COMSOL termination",
                )
            expected[target.machine_id] = self.machine_control_fingerprint(target.machine_id, action)
            impact[target.machine_id] = {
                "owner_mode": policy.owner_mode.value,
                "admin_override": policy.admin_mode_override.value if policy.admin_mode_override else None,
                "effective_mode": policy.effective_mode().value,
                "current_target_capacity": config.target_concurrent_units,
                "validated_hard_cap": min(policy.max_concurrent_units, config.max_concurrent_units),
                "accepted_hard_cap": config.accepted_hard_capacity_units,
                "hard_capacity_pending_acceptance": config.hard_capacity_pending_acceptance,
                "active_attempt_count": machine.metrics.running_units,
                "external_comsol_process_count": status.external_comsol_process_count if status else 0,
                "external_comsol_process_set_hash": status.external_comsol_process_set_hash if status else None,
            }
        now = datetime.now(timezone.utc)
        canonical = json.dumps(
            {
                "action": action.value,
                "targets": [target.model_dump(mode="json") for target in targets],
                "expected": expected,
                "reason": reason,
                "issued_by": actor_id,
                "created_at": now.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        ticket = MachineControlTicket(
            action=action,
            targets=targets,
            reason=reason,
            expected_fingerprints=expected,
            impact=impact,
            confirmation_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            requires_break_glass=action == MachineControlAction.EMERGENCY_STOP_HOST,
            issued_by=actor_id,
            created_at=now,
            expires_at=now + timedelta(minutes=5),
        )
        self.repository.put_machine_control_ticket(ticket)
        self._event(
            "machine_control.previewed",
            actor_id,
            "control_ticket",
            ticket.ticket_id,
            action=action.value,
            machine_ids=machine_ids,
            requires_break_glass=ticket.requires_break_glass,
        )
        return ticket

    def preview_runtime_control(
        self,
        action: MachineControlAction,
        machine_id: str,
        *,
        runtime_snapshot: dict,
        reason: str,
        actor_id: str,
    ) -> MachineControlTicket:
        if action not in {
            MachineControlAction.PROMOTE_RUNTIME,
            MachineControlAction.ROLLBACK_RUNTIME,
        }:
            raise ValueError("unsupported runtime control action")
        reason = reason.strip()
        if not reason:
            raise ValueError("runtime promotion and rollback require a reason")
        config = self.repository.get_machine_execution_config(machine_id)
        status = self.repository.get_machine_operational_status(machine_id)
        if config is None or not config.enabled:
            raise ValueError("runtime control requires an enabled accepted machine")
        if status is None or status.supervisor_state != SupervisorState.ONLINE:
            raise ValueError("runtime control requires a live supervisor")
        if runtime_snapshot.get("active_run_ids"):
            raise ValueError("runtime control requires an idle supervisor")
        running_version = str(runtime_snapshot.get("running_runtime_version") or "")
        formal_version = str(config.runtime_version or "")
        target_version = str(runtime_snapshot.get("target_runtime_version") or "")
        if action == MachineControlAction.PROMOTE_RUNTIME:
            if not running_version or running_version == formal_version:
                raise ValueError("no running candidate runtime is available for promotion")
            target_version = running_version
        elif not target_version or target_version == running_version:
            raise ValueError("no previous runtime is available for rollback")

        target = MachineControlTarget(machine_id=machine_id)
        state_fingerprint = self.runtime_control_fingerprint(machine_id)
        snapshot_payload = {
            "running_runtime_version": running_version,
            "formal_runtime_version": formal_version,
            "target_runtime_version": target_version,
            "supervisor_instance_fingerprint": runtime_snapshot.get("supervisor_instance_fingerprint"),
            "startup_fingerprint": runtime_snapshot.get("startup_fingerprint"),
            "target_runtime_available": bool(runtime_snapshot.get("target_runtime_available")),
            "active_run_ids": sorted(runtime_snapshot.get("active_run_ids") or []),
        }
        combined_fingerprint = hashlib.sha256(json.dumps(
            {"state": state_fingerprint, "runtime": snapshot_payload},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc)
        canonical = json.dumps(
            {
                "action": action.value,
                "machine_id": machine_id,
                "expected": combined_fingerprint,
                "reason": reason,
                "issued_by": actor_id,
                "created_at": now.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        ticket = MachineControlTicket(
            action=action,
            targets=[target],
            reason=reason,
            expected_fingerprints={machine_id: combined_fingerprint},
            impact={machine_id: snapshot_payload},
            confirmation_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            issued_by=actor_id,
            created_at=now,
            expires_at=now + timedelta(minutes=5),
        )
        self.repository.put_machine_control_ticket(ticket)
        self._event(
            "machine_runtime_control.previewed",
            actor_id,
            "control_ticket",
            ticket.ticket_id,
            action=action.value,
            machine_id=machine_id,
            running_runtime_version=running_version,
            formal_runtime_version=formal_version,
            target_runtime_version=target_version,
        )
        return ticket

    @atomic_confirmation("runtime")
    def confirm_runtime_control(
        self,
        ticket_id: str,
        confirmation_hash: str,
        *,
        runtime_snapshot: dict,
        actor_id: str,
    ) -> ControlOperationRun:
        ticket = self.repository.get_machine_control_ticket(ticket_id)
        now = datetime.now(timezone.utc)
        if (
            ticket is None
            or ticket.action not in {
                MachineControlAction.PROMOTE_RUNTIME,
                MachineControlAction.ROLLBACK_RUNTIME,
            }
            or ticket.confirmation_hash != confirmation_hash
            or ticket.expires_at <= now
        ):
            raise ValueError("runtime control preview is invalid or expired")
        target = ticket.targets[0]
        state_fingerprint = self.runtime_control_fingerprint(target.machine_id)
        config = self.repository.get_machine_execution_config(target.machine_id)
        assert config is not None
        current_payload = {
            "running_runtime_version": str(runtime_snapshot.get("running_runtime_version") or ""),
            "formal_runtime_version": str(config.runtime_version or ""),
            "target_runtime_version": str(runtime_snapshot.get("target_runtime_version") or ""),
            "supervisor_instance_fingerprint": runtime_snapshot.get("supervisor_instance_fingerprint"),
            "startup_fingerprint": runtime_snapshot.get("startup_fingerprint"),
            "target_runtime_available": bool(runtime_snapshot.get("target_runtime_available")),
            "active_run_ids": sorted(runtime_snapshot.get("active_run_ids") or []),
        }
        expected_payload = ticket.impact[target.machine_id]
        current_fingerprint = hashlib.sha256(json.dumps(
            {"state": state_fingerprint, "runtime": current_payload},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        if (
            current_fingerprint != ticket.expected_fingerprints[target.machine_id]
            or current_payload != expected_payload
        ):
            raise ValueError("runtime state changed after preview; preview again")
        run = ControlOperationRun(
            ticket_id=ticket.ticket_id,
            action=ticket.action,
            state=ControlOperationState.ACCEPTED,
            requested_by=actor_id,
            reason=ticket.reason,
            request_targets=ticket.targets,
            impact=ticket.impact,
            targets=[ControlTargetResult(
                machine_id=target.machine_id,
                state=ControlTargetState.ACKNOWLEDGED,
                message="runtime operation accepted for bounded execution",
            )],
        )
        self.repository.put_control_operation_run(run)
        self.repository.delete_machine_control_ticket(ticket.ticket_id)
        self._event(
            "machine_runtime_control.accepted",
            actor_id,
            "control_operation",
            run.operation_id,
            action=ticket.action.value,
            machine_id=target.machine_id,
        )
        return run

    def _requeue_unstarted_assignments(self, machine_id: str, *, actor_id: str) -> int:
        count = 0
        now = datetime.now(timezone.utc)
        for job in self.repository.list_operational_jobs(
            statuses={JobStatus.QUEUED, JobStatus.RUNNING},
            machine_id=machine_id,
            limit=500,
        ):
            changed = False
            for unit in job.work_units:
                if unit.assigned_machine_id != machine_id or unit.status != WorkUnitStatus.ASSIGNED:
                    continue
                attempt = self._current_attempt(unit)
                if attempt is not None and attempt.state == "assigned" and attempt.started_at is None:
                    attempt.state = "cancelled"
                    attempt.finished_at = now
                    attempt.failure_reason = "administrator paused machine before remote start"
                unit.status = WorkUnitStatus.QUEUED
                unit.assigned_machine_id = None
                count += 1
                changed = True
            if changed:
                job.status = JobStatus.QUEUED
                self.repository.put_job(job)
                self._event(
                    "machine.assigned_units_requeued",
                    actor_id,
                    "job",
                    job.job_id,
                    machine_id=machine_id,
                )
        return count

    @atomic_confirmation("machine")
    def confirm_machine_control(
        self,
        ticket_id: str,
        confirmation_hash: str,
        *,
        actor_id: str,
        break_glass_pin: str | None = None,
        typed_machine_id: str | None = None,
        process_set_hash: str | None = None,
    ) -> tuple[ControlOperationRun, list[MachineCommand]]:
        ticket = self.repository.get_machine_control_ticket(ticket_id)
        now = datetime.now(timezone.utc)
        if (
            ticket is None
            or ticket.confirmation_hash != confirmation_hash
            or ticket.expires_at <= now
        ):
            raise ValueError("machine control preview is invalid or expired")
        for target in ticket.targets:
            if self.machine_control_fingerprint(target.machine_id, ticket.action) != ticket.expected_fingerprints[target.machine_id]:
                raise ValueError("machine state changed after preview; preview the whole batch again")
        if ticket.requires_break_glass:
            target = ticket.targets[0]
            expected_process_hash = ticket.impact[target.machine_id].get("external_comsol_process_set_hash")
            if typed_machine_id != target.machine_id:
                raise ValueError("full machine ID confirmation does not match")
            if not break_glass_pin or not self.verify_break_glass_pin(break_glass_pin):
                raise ValueError("break-glass PIN is invalid or not configured")
            if not process_set_hash or process_set_hash != expected_process_hash:
                raise ValueError("COMSOL process set changed after preview")

        commands: list[MachineCommand] = []
        results: list[ControlTargetResult] = []
        local_actions = {
            MachineControlAction.SET_ADMIN_MODE,
            MachineControlAction.CLEAR_ADMIN_MODE,
            MachineControlAction.ACCEPT_HARD_CAPACITY,
        }
        for target in ticket.targets:
            if ticket.action == MachineControlAction.SET_ADMIN_MODE:
                policy = self.repository.get_policy(target.machine_id)
                assert policy is not None
                policy.admin_mode_override = target.requested_mode
                policy.admin_override_reason = ticket.reason
                policy.admin_override_actor = actor_id
                policy.admin_override_at = now
                self.repository.put_policy(policy, admin_override_authorized=True)
                if target.requested_mode == MachineMode.PAUSED:
                    self._requeue_unstarted_assignments(target.machine_id, actor_id=actor_id)
            elif ticket.action == MachineControlAction.CLEAR_ADMIN_MODE:
                policy = self.repository.get_policy(target.machine_id)
                assert policy is not None
                policy.admin_mode_override = None
                policy.admin_override_reason = ""
                policy.admin_override_actor = None
                policy.admin_override_at = None
                self.repository.put_policy(policy, admin_override_authorized=True)
            elif ticket.action == MachineControlAction.SET_TARGET_CAPACITY:
                config = self.repository.get_machine_execution_config(target.machine_id)
                assert config is not None and target.target_concurrent_units is not None
                config.target_concurrent_units = target.target_concurrent_units
                self.repository.put_machine_execution_config(config)
            elif ticket.action == MachineControlAction.SET_HARD_CAPACITY:
                policy = self.repository.get_policy(target.machine_id)
                config = self.repository.get_machine_execution_config(target.machine_id)
                assert policy is not None and config is not None and target.hard_capacity_units is not None
                accepted_cap = config.accepted_hard_capacity_units or min(
                    policy.max_concurrent_units, config.max_concurrent_units
                )
                accepted_cap = min(accepted_cap, target.hard_capacity_units)
                policy.max_concurrent_units = target.hard_capacity_units
                config.max_concurrent_units = target.hard_capacity_units
                config.target_concurrent_units = min(config.target_concurrent_units, target.hard_capacity_units)
                config.accepted_hard_capacity_units = accepted_cap
                config.hard_capacity_pending_acceptance = target.hard_capacity_units > accepted_cap
                if config.hard_capacity_pending_acceptance:
                    config.hard_capacity_forced_by = actor_id
                    config.hard_capacity_forced_at = now
                    config.hard_capacity_force_reason = ticket.reason
                    config.hard_capacity_acceptance_reference = None
                    config.hard_capacity_accepted_by = None
                    config.hard_capacity_accepted_at = None
                else:
                    config.hard_capacity_forced_by = None
                    config.hard_capacity_forced_at = None
                    config.hard_capacity_force_reason = ""
                self.repository.put_policy(policy)
                self.repository.put_machine_execution_config(config)
            elif ticket.action == MachineControlAction.ACCEPT_HARD_CAPACITY:
                config = self.repository.get_machine_execution_config(target.machine_id)
                assert config is not None and target.acceptance_reference is not None
                config.accepted_hard_capacity_units = config.max_concurrent_units
                config.hard_capacity_pending_acceptance = False
                config.hard_capacity_acceptance_reference = target.acceptance_reference.strip()
                config.hard_capacity_accepted_by = actor_id
                config.hard_capacity_accepted_at = now
                self.repository.put_machine_execution_config(config)

            if ticket.action in local_actions:
                results.append(ControlTargetResult(
                    machine_id=target.machine_id,
                    state=ControlTargetState.COMPLETED,
                    message="control state persisted",
                ))
                continue
            config = self.repository.get_machine_execution_config(target.machine_id)
            assert config is not None and config.root_uuid and config.runtime_version
            command = MachineCommand(
                machine_id=target.machine_id,
                action=ticket.action,
                root_uuid=config.root_uuid,
                runtime_version=config.runtime_version,
                nonce=secrets.token_hex(16),
                reason=ticket.reason,
                expected_process_set_hash=(
                    ticket.impact[target.machine_id].get("external_comsol_process_set_hash")
                    if ticket.action == MachineControlAction.EMERGENCY_STOP_HOST
                    else None
                ),
                target_concurrent_units=target.target_concurrent_units,
                hard_capacity_units=target.hard_capacity_units,
                created_at=now,
                expires_at=now + timedelta(minutes=5),
            )
            commands.append(command)
            results.append(ControlTargetResult(
                machine_id=target.machine_id,
                command_id=command.command_id,
                message="accepted for remote execution",
            ))

        run = ControlOperationRun(
            ticket_id=ticket.ticket_id,
            action=ticket.action,
            state=(ControlOperationState.COMPLETED if not commands else ControlOperationState.ACCEPTED),
            requested_by=actor_id,
            reason=ticket.reason,
            request_targets=ticket.targets,
            impact=ticket.impact,
            targets=results,
        )
        self.repository.put_control_operation_run(run)
        self.repository.delete_machine_control_ticket(ticket.ticket_id)
        self._event(
            "machine_control.accepted",
            actor_id,
            "control_operation",
            run.operation_id,
            action=ticket.action.value,
            machine_ids=[target.machine_id for target in ticket.targets],
        )
        return run, commands

    @atomic_metadata
    def update_control_target(
        self,
        operation_id: str,
        result: ControlTargetResult,
        *,
        actor_id: str,
    ) -> ControlOperationRun:
        run = self.repository.get_control_operation_run(operation_id)
        if run is None:
            raise KeyError(f"control operation not found: {operation_id}")
        previous = next((item for item in run.targets if item.machine_id == result.machine_id), None)
        if (previous is not None and previous.state in {ControlTargetState.COMPLETED, ControlTargetState.FAILED}
                and result.state not in {ControlTargetState.COMPLETED, ControlTargetState.FAILED}):
            return run
        run.targets = [result if item.machine_id == result.machine_id else item for item in run.targets]
        states = {item.state for item in run.targets}
        if states == {ControlTargetState.COMPLETED}:
            run.state = ControlOperationState.COMPLETED
        elif ControlTargetState.FAILED in states and states <= {ControlTargetState.COMPLETED, ControlTargetState.FAILED}:
            run.state = (
                ControlOperationState.FAILED
                if states == {ControlTargetState.FAILED}
                else ControlOperationState.PARTIAL_FAILED
            )
        elif ControlTargetState.ACKNOWLEDGED in states:
            run.state = ControlOperationState.REMOTE_ACKNOWLEDGED
        run.updated_at = datetime.now(timezone.utc)
        self.repository.put_control_operation_run(run)
        self._event(
            "machine_control.target_updated",
            actor_id,
            "control_operation",
            operation_id,
            machine_id=result.machine_id,
            state=result.state.value,
            message=result.message,
        )
        return run

    def preview_dispatcher_control(
        self,
        action: DispatcherControlAction,
        *,
        fingerprint: str,
        impact: dict,
        reason: str,
        actor_id: str,
    ) -> DispatcherControlTicket:
        reason = reason.strip()
        if action in {
            DispatcherControlAction.STOP,
            DispatcherControlAction.RESTART,
            DispatcherControlAction.FORCE_STOP,
        } and not reason:
            raise ValueError("this Dispatcher action requires a reason")
        now = datetime.now(timezone.utc)
        canonical = json.dumps(
            {
                "action": action.value,
                "fingerprint": fingerprint,
                "reason": reason,
                "issued_by": actor_id,
                "created_at": now.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        ticket = DispatcherControlTicket(
            action=action,
            reason=reason,
            expected_fingerprint=fingerprint,
            impact=impact,
            confirmation_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            issued_by=actor_id,
            created_at=now,
            expires_at=now + timedelta(minutes=5),
        )
        self.repository.put_dispatcher_control_ticket(ticket)
        self._event(
            "dispatcher_control.previewed",
            actor_id,
            "dispatcher_control_ticket",
            ticket.ticket_id,
            action=action.value,
        )
        return ticket

    @atomic_confirmation("dispatcher")
    def confirm_dispatcher_control(
        self,
        ticket_id: str,
        confirmation_hash: str,
        *,
        current_fingerprint: str,
        actor_id: str,
    ) -> ControlOperationRun:
        ticket = self.repository.get_dispatcher_control_ticket(ticket_id)
        now = datetime.now(timezone.utc)
        if (
            ticket is None
            or ticket.confirmation_hash != confirmation_hash
            or ticket.expires_at <= now
        ):
            raise ValueError("Dispatcher control preview is invalid or expired")
        if current_fingerprint != ticket.expected_fingerprint:
            raise ValueError("Dispatcher state changed after preview")
        run = ControlOperationRun(
            ticket_id=ticket.ticket_id,
            action=ticket.action,
            requested_by=actor_id,
            reason=ticket.reason,
            request_targets=[],
            impact={"dispatcher": ticket.impact},
            targets=[ControlTargetResult(
                machine_id="dispatcher",
                state=ControlTargetState.ACKNOWLEDGED,
                message="accepted by fixed Dispatcher process controller",
            )],
        )
        self.repository.put_control_operation_run(run)
        self.repository.delete_dispatcher_control_ticket(ticket.ticket_id)
        self._event(
            "dispatcher_control.accepted",
            actor_id,
            "control_operation",
            run.operation_id,
            action=ticket.action.value,
        )
        return run

    @alert_transition_confirmation
    def transition_alert(
        self,
        alert_id: str,
        status: AlertStatus,
        *,
        actor_id: str,
        snoozed_until: datetime | None = None,
        expected_state: dict | None = None,
    ) -> AlertRecord:
        alert = self.repository.get_alert(alert_id)
        if alert is None:
            raise KeyError(f"alert not found: {alert_id}")
        if expected_state is not None and any(
            getattr(alert, field) != value for field, value in expected_state.items()
        ):
            raise ValueError("alert changed after the original request; refresh before a new action")
        if alert.status == AlertStatus.RESOLVED and status != AlertStatus.RESOLVED:
            raise ValueError("a resolved alert cannot be reopened by a stale transition")
        if status == AlertStatus.ACTIVE:
            raise ValueError("active alerts are created by telemetry, not administrator transitions")
        if alert.status == status and status != AlertStatus.SNOOZED:
            return alert
        now = datetime.now(timezone.utc)
        alert.status = status
        if status == AlertStatus.ACKNOWLEDGED:
            alert.acknowledged_by = actor_id
            alert.acknowledged_at = now
        elif status == AlertStatus.SNOOZED:
            if snoozed_until is None or snoozed_until <= now:
                raise ValueError("snooze must end in the future")
            alert.snoozed_until = snoozed_until
        elif status == AlertStatus.RESOLVED:
            alert.resolved_at = now
        self.repository.put_alert(alert)
        self._event(
            "alert.status_changed",
            actor_id,
            "alert",
            alert_id,
            status=status.value,
            snoozed_until=snoozed_until.isoformat() if snoozed_until else None,
        )
        return alert

    def feature_settings(self) -> FeatureSettings:
        return self.repository.get_feature_settings()

    @atomic_metadata
    def update_feature_settings(self, settings: FeatureSettings, *, actor_id: str) -> FeatureSettings:
        current = self.repository.get_feature_settings()
        for name in ("scheduling_policy", "scheduling_revision", "scheduling_confirmation"):
            if name in settings.model_fields_set and getattr(settings,name) != getattr(current,name):
                raise ValueError("scheduling changes require their dedicated preview/confirm")
            setattr(settings,name,getattr(current,name))
        settings.updated_at = datetime.now(timezone.utc)
        self.repository.put_feature_settings(settings)
        # Keep the non-secret supervisor configuration aligned so the next
        # sealed-runtime deployment/reload consumes exactly what the website
        # displays. Running supervisors are not restarted here.
        for config in self.repository.list_machine_execution_configs():
            config.telemetry_policy = settings.telemetry_policy
            self.repository.put_machine_execution_config(config)
        self._event(
            "feature_settings.updated",
            actor_id,
            "feature_settings",
            settings.settings_id,
            visibility=settings.visibility.value,
            pressure_policy=settings.pressure_policy.model_dump(mode="json"),
            telemetry_policy=settings.telemetry_policy.model_dump(mode="json"),
        )
        return settings

    def preview_resource_policy(self, policy: ResourcePolicy) -> dict:
        if self.repository.get_profile(policy.profile_id) is None:
            raise KeyError(f"execution profile not found: {policy.profile_id}")
        current = self.repository.get_feature_settings().resource_policies.get(policy.profile_id)
        current_revision = current.revision if current is not None else 0
        candidate = policy.model_copy(update={
            "revision": current_revision + 1,
            "updated_at": datetime.now(timezone.utc),
        })
        fingerprint_payload = {
            "profile_id": policy.profile_id,
            "expected_revision": current_revision,
            "candidate": candidate.model_dump(mode="json", exclude={"updated_at"}),
        }
        return {
            "profile_id": policy.profile_id,
            "expected_revision": current_revision,
            "candidate": candidate.model_dump(mode="json"),
            "confirmation_hash": sha256_value(fingerprint_payload),
            "impact": {
                "running_attempts_unchanged": True,
                "unstarted_units_use_new_revision": True,
                "baseline_before": (
                    current.baseline.model_dump(mode="json") if current is not None else None
                ),
                "baseline_after": candidate.baseline.model_dump(mode="json"),
            },
        }

    @atomic_metadata
    def confirm_resource_policy(
        self,
        policy: ResourcePolicy,
        *,
        expected_revision: int,
        confirmation_hash: str,
        actor_id: str,
    ) -> ResourcePolicy:
        preview = self.preview_resource_policy(policy)
        if preview["expected_revision"] != expected_revision:
            raise ValueError("resource policy changed after preview; generate a new preview")
        if not hmac.compare_digest(preview["confirmation_hash"], confirmation_hash):
            raise ValueError("resource policy confirmation hash does not match the preview")
        candidate = ResourcePolicy.model_validate(preview["candidate"])
        settings = self.repository.get_feature_settings()
        settings.resource_policies[candidate.profile_id] = candidate
        settings.updated_at = datetime.now(timezone.utc)
        self.repository.put_feature_settings(settings)
        self._event(
            "resource_policy.updated",
            actor_id,
            "execution_profile",
            candidate.profile_id,
            revision=candidate.revision,
            baseline=candidate.baseline.model_dump(mode="json"),
            minimum=candidate.minimum.model_dump(mode="json"),
            maximum=candidate.maximum.model_dump(mode="json"),
            automatic_adjustment=candidate.automatic_adjustment,
        )
        return candidate

    def update_machine_ssh_timeouts(
        self,
        machine_id: str,
        *,
        ssh_connect_timeout_s: int,
        ssh_status_timeout_s: int,
        reason: str,
        actor_id: str,
    ) -> MachineExecutionConfig:
        """Adjust center transport deadlines without changing execution acceptance."""
        machine = self.repository.get_machine(machine_id)
        existing = self.repository.get_machine_execution_config(machine_id)
        if machine is None or existing is None:
            raise KeyError(f"machine execution config not found: {machine_id}")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
            raise ValueError("SSH timeout changes require a nonblank reason of at most 1000 characters")
        names = ("ssh_connect_timeout_s", "ssh_status_timeout_s")
        before = {name: getattr(existing, name) for name in names}
        requested = {
            "ssh_connect_timeout_s": ssh_connect_timeout_s,
            "ssh_status_timeout_s": ssh_status_timeout_s,
        }
        updated = MachineExecutionConfig.model_validate({
            **existing.model_dump(mode="python"), **requested,
        })
        if before == requested:
            raise ValueError("SSH timeout configuration is unchanged")
        # The general execution-config writer evaluates capacity acceptance.
        # These two transport-only fields do not grant execution or capacity;
        # preserve every existing scientific and hard-capacity fact verbatim.
        self.repository.put_machine_execution_config(updated)
        self._event(
            "machine.ssh_timeouts_updated", actor_id, "machine", machine_id,
            reason=reason.strip(), owner_user_id=machine.owner_user_id,
            authorization_scope="administrator SSH transport deadline adjustment",
            before=before, after={name: getattr(updated, name) for name in names},
            existing_attempt_resources_preserved=True,
            capacity_and_scientific_evidence_preserved=True,
        )
        return updated

    def admit_cached_runtime(self, evidence, *, reason: str, actor_id: str,
                             cache_runtime: str = STABLE_RUNTIME_VERSION) -> MachineExecutionConfig:
        """Record exact cached execution inventory without changing the primary.

        The remote inventory and import route are read back by the operator.
        Here their expected archive is independently selected by the server,
        rather than accepting a remotely chosen scientific implementation.
        """
        from .member_runtime_verification import inventory_digest
        from .runtime_cache_admission import (CachedRuntimeAdmission, CACHE_ADMISSION_KEY, merge_cache_admission,
                                             server_cached_runtime_files, SERVER_CACHE_ARCHIVE_PINS)
        evidence = CachedRuntimeAdmission.model_validate(evidence)
        if not reason.strip():
            raise ValueError("cached runtime admission requires an operator reason")
        if evidence.cache_runtime != cache_runtime:
            raise ValueError("desired cached runtime differs from its original inventory evidence")
        if not self.runtime_policy.accepts_worker_runtime(cache_runtime):
            raise ValueError("cached runtime is not accepted by the current worker runtime policy")
        files = server_cached_runtime_files(cache_runtime)
        if (evidence.archive_sha256 != SERVER_CACHE_ARCHIVE_PINS[cache_runtime]
                or evidence.manifest_sha256 != hashlib.sha256(files["runtime-manifest.json"]).hexdigest()
                or evidence.inventory_sha256 != inventory_digest(files)
                or evidence.file_count != len(files)):
            raise ValueError("cached runtime inventory differs from the server-pinned complete archive")
        machine = self.repository.get_machine(evidence.machine_id)
        config = self.repository.get_machine_execution_config(evidence.machine_id)
        if machine is None or config is None:
            raise KeyError("cached runtime machine execution binding not found")
        value, changed = merge_cache_admission(machine, config, evidence)
        if not changed:
            return config
        config.execution_provenance[CACHE_ADMISSION_KEY] = value
        # This producer owns runtime_cache_*; general config PUT cannot mint or
        # replace the evidence. Primary runtime, capacity and owner mode remain.
        self.repository.put_machine_execution_config(config)
        self._event("machine.cached_runtime_admitted", actor_id, "machine", machine.machine_id,
                    reason=reason.strip(), evidence=evidence.model_dump(mode="json"),
                    primary_runtime_unchanged=True, scientific_approval_unchanged=True,
                    expires_at=None)
        return config

    def put_machine_execution_config(
        self,
        config: MachineExecutionConfig,
        *,
        actor_id: str,
    ) -> MachineExecutionConfig:
        machine = self.repository.get_machine(config.machine_id)
        if machine is None:
            raise KeyError(f"machine not found: {config.machine_id}")
        validate_remote_root_path(config.remote_root)
        known_profiles = {profile.profile_id for profile in self.repository.list_profiles()}
        unknown_profile_limits = sorted(set(config.profile_concurrency_limits) - known_profiles)
        if unknown_profile_limits:
            raise ValueError(
                f"profile concurrency limits reference unknown profiles: {unknown_profile_limits}"
            )
        excessive_profile_limits = {
            profile_id: limit
            for profile_id, limit in config.profile_concurrency_limits.items()
            if limit > config.max_concurrent_units
        }
        if excessive_profile_limits:
            raise ValueError(
                "profile concurrency limits cannot exceed machine max concurrency: "
                f"{excessive_profile_limits}"
            )
        existing = self.repository.get_machine_execution_config(config.machine_id)
        owned = {k:v for k,v in (existing.execution_provenance.items() if existing else [])
                 if k.startswith(('scientific_audit_', 'runtime_cache_'))}
        supplied = {k:v for k,v in config.execution_provenance.items()
                    if k.startswith(('scientific_audit_', 'runtime_cache_'))}
        if any(k not in owned or owned[k] != v for k,v in supplied.items()):
            raise ValueError('scientific and runtime inventory evidence is owned by its producer')
        config.execution_provenance.update(owned)
        if existing and existing.remote_root != config.remote_root:
            active = {
                RemoteRunState.STAGED,
                RemoteRunState.PREPARED,
                RemoteRunState.QUEUED,
                RemoteRunState.RUNNING,
                RemoteRunState.CANCEL_PENDING,
            }
            if any(run.state in active for run in self.repository.list_remote_runs(config.machine_id)):
                raise ValueError("cannot switch remote root while work units are active")
            config.root_uuid = None
            config.enabled = False
        passed_levels = {
            int(check.check_id.rsplit("_", 1)[1])
            for run in self.repository.list_ssh_acceptance_runs()
            if run.worker_id == config.machine_id
            and not any(c.check_id == 'scientific_context' for c in run.checks)
            for check in run.checks
            if (
                check.status.value == "passed"
                or (
                    check.status.value == "warning"
                    and check.evidence.get("operational_execution_passed") is True
                )
            )
            and check.check_id.startswith("concurrency_")
            and check.check_id.rsplit("_", 1)[1].isdigit()
        }
        highest_passed = max(passed_levels, default=0)
        full_acceptance = any(
            run.worker_id == config.machine_id and run.status.value == "passed"
            and not any(c.check_id == 'scientific_context' for c in run.checks)
            for run in self.repository.list_ssh_acceptance_runs()
        )
        startup_rank = {"manual": 0, "logon": 1, "boot": 2}
        persisted_hard_cap = (
            existing.accepted_hard_capacity_units
            if existing and existing.accepted_hard_capacity_units is not None
            else (existing.max_concurrent_units if existing else 0)
        )
        requires_acceptance_evidence = bool(
            config.enabled
            and (
                existing is None
                or not existing.enabled
                or config.max_concurrent_units > persisted_hard_cap
                or config.target_concurrent_units > persisted_hard_cap
                or startup_rank[config.supervisor_startup] > startup_rank[existing.supervisor_startup]
            )
        )
        from .admission_governance import trust_first_execution, trust_readiness_blockers
        if config.enabled and trust_first_execution(config):
            reasons = trust_readiness_blockers(machine, self.repository.get_policy(config.machine_id), config,
                self.repository.get_machine_operational_status(config.machine_id))
            if reasons:
                raise ValueError("trust-first execution prerequisites: " + ", ".join(reasons))
            requires_acceptance_evidence = False
        if (
            requires_acceptance_evidence
            and config.max_concurrent_units > max(1, highest_passed)
        ):
            raise ValueError("requested concurrency has not passed SSH COMSOL acceptance")
        if requires_acceptance_evidence and (
            not full_acceptance
            or highest_passed < config.target_concurrent_units
            or not config.root_uuid
        ):
            raise ValueError("SSH production execution cannot be enabled before full acceptance")
        if config.conditional_production == "enabled" and (
            not config.enabled
            or config.operational_execution != "passed"
            or config.supervisor_startup not in {"logon", "boot"}
            or config.numeric_equivalence not in {"passed", "warning"}
        ):
            raise ValueError("conditional production requires operational, startup, and numeric status")
        if config.numeric_equivalence == "warning" and not config.capability_warnings:
            raise ValueError("numeric warning requires a visible capability warning")
        if requires_acceptance_evidence and config.supervisor_startup in {"logon", "boot"} and (
            not full_acceptance or highest_passed < config.target_concurrent_units
        ):
            raise ValueError("automatic supervisor startup cannot be enabled before full acceptance")
        if config.tunnel_startup in {"logon", "boot"} and not config.coordinator_host:
            raise ValueError("tunnel startup requires a coordinator host")
        self.repository.put_machine_execution_config(config)
        self._event(
            "machine.execution_config_updated",
            actor_id,
            "machine",
            config.machine_id,
            remote_root=config.remote_root,
            enabled=config.enabled,
            max_concurrent_units=config.max_concurrent_units,
            profile_concurrency_limits=config.profile_concurrency_limits,
        )
        return config

    def review_scientific_acceptance(
        self, machine_id: str, *, run_id: str, report_sha256: str, reason: str,
        actor_id: str,
    ) -> MachineExecutionConfig:
        """Audited numerics-only review; producer report and policies are unchanged."""
        from .scientific_acceptance_review import review_scientific_acceptance
        return review_scientific_acceptance(self.repository, machine_id, run_id=run_id,
            report_sha256=report_sha256, reason=reason, actor_id=actor_id)

    @atomic_metadata
    def update_machine_execution_tuning(
        self,
        machine_id: str,
        *,
        disk_reserve_gib: int,
        success_retention_days: int,
        failure_retention_days: int,
        poll_interval_s: int,
        profile_concurrency_limits: dict[str, int],
        actor_id: str,
    ) -> MachineExecutionConfig:
        """Update daily tuning without reopening immutable acceptance gates."""
        config = self.repository.get_machine_execution_config(machine_id)
        if config is None:
            raise KeyError(f"machine execution config not found: {machine_id}")
        known_profiles = {profile.profile_id for profile in self.repository.list_profiles()}
        unknown_profiles = sorted(set(profile_concurrency_limits) - known_profiles)
        if unknown_profiles:
            raise ValueError(f"profile concurrency limits reference unknown profiles: {unknown_profiles}")
        excessive_limits = {
            profile_id: limit
            for profile_id, limit in profile_concurrency_limits.items()
            if limit < 1 or limit > config.max_concurrent_units
        }
        if excessive_limits:
            raise ValueError(
                "profile concurrency limits must be between 1 and machine max concurrency: "
                f"{excessive_limits}"
            )
        config.disk_reserve_gib = disk_reserve_gib
        config.success_retention_days = success_retention_days
        config.failure_retention_days = failure_retention_days
        config.poll_interval_s = poll_interval_s
        config.profile_concurrency_limits = profile_concurrency_limits
        config.updated_at = datetime.now(timezone.utc)
        self.repository.put_machine_execution_config(config)
        self._event(
            "machine.execution_tuning_updated",
            actor_id,
            "machine",
            machine_id,
            disk_reserve_gib=disk_reserve_gib,
            success_retention_days=success_retention_days,
            failure_retention_days=failure_retention_days,
            poll_interval_s=poll_interval_s,
            profile_concurrency_limits=profile_concurrency_limits,
        )
        return config

    def set_machine_conditional_readiness(
        self,
        machine_id: str,
        *,
        operational_execution: str,
        conditional_production: str,
        startup_after_reboot: str,
        numeric_equivalence: str,
        capability_warnings: list[str],
        execution_provenance: dict[str, str],
        actor_id: str,
        owner_mode: MachineMode = MachineMode.OPEN,
        profile_concurrency_limits: dict[str, int] | None = None,
    ) -> MachineExecutionConfig:
        config = self.repository.get_machine_execution_config(machine_id)
        if config is None:
            raise KeyError(f"machine execution config not found: {machine_id}")
        config.operational_execution = operational_execution
        config.conditional_production = conditional_production
        config.startup_after_reboot = startup_after_reboot
        config.numeric_equivalence = numeric_equivalence
        config.capability_warnings = capability_warnings
        config.execution_provenance = execution_provenance
        config.enabled = conditional_production == "enabled"
        if profile_concurrency_limits is not None:
            config.profile_concurrency_limits = profile_concurrency_limits
        saved = self.put_machine_execution_config(config, actor_id=actor_id)
        policy = self.repository.get_policy(machine_id)
        if policy is None:
            raise KeyError(f"machine policy not found: {machine_id}")
        policy.owner_mode = owner_mode
        self.repository.put_policy(policy)
        self._event(
            "machine.conditional_readiness_updated",
            actor_id,
            "machine",
            machine_id,
            operational_execution=operational_execution,
            conditional_production=conditional_production,
            startup_after_reboot=startup_after_reboot,
            numeric_equivalence=numeric_equivalence,
            capability_warnings=capability_warnings,
            execution_provenance=execution_provenance,
            owner_mode=owner_mode.value,
            profile_concurrency_limits=config.profile_concurrency_limits,
        )
        return saved

    def put_remote_run(self, run: RemoteRunRecord, *, actor_id: str,
                       expected_attempt_id: str | None = None) -> RemoteRunRecord:
        snapshot = self.repository.get_operational_job(run.job_id)
        if snapshot is not None:
            def update_attempt(current: JobEnvelope) -> None:
                unit = next((candidate for candidate in current.work_units if candidate.work_unit_id == run.work_unit_id), None)
                if unit is None:
                    raise KeyError(f"work unit not found: {run.work_unit_id}")
                bound = expected_attempt_id
                matching = [attempt for attempt in unit.attempts if attempt.external_run_id == run.external_run_id]
                if bound is None and matching:
                    if len(matching) != 1:
                        raise ValueError("remote-run Attempt binding is ambiguous")
                    bound = matching[0].attempt_id
                attempt = self._fenced_current_attempt(unit, bound)
                if attempt is not None:
                    if attempt.external_run_id not in {None, run.external_run_id}:
                        raise ValueError("remote run does not match the current Attempt binding")
                    if attempt.machine_id not in {None, run.machine_id}:
                        raise ValueError("remote run machine does not match the current Attempt binding")
                    attempt.external_run_id = run.external_run_id
                    attempt.machine_id = run.machine_id
                    if run.state == RemoteRunState.RUNNING:
                        attempt.state = "running"
                    elif run.state == RemoteRunState.COMPLETED:
                        attempt.state = "completed"
                    elif run.state in {RemoteRunState.FAILED, RemoteRunState.INTERRUPTED}:
                        attempt.state = "failed"
                    elif run.state == RemoteRunState.CANCELLED:
                        attempt.state = "cancelled"
            self.repository.mutate_job(run.job_id, update_attempt, hydrate_blobs=False)
        elif expected_attempt_id is not None:
            raise KeyError(f"job not found: {run.job_id}")
        self.repository.put_remote_run(run)
        self._event(
            "remote_run.updated",
            actor_id,
            "remote_run",
            run.external_run_id,
            machine_id=run.machine_id,
            work_unit_id=run.work_unit_id,
            state=run.state.value,
        )
        return run

    def put_ssh_acceptance_run(
        self,
        run: SshAcceptanceRun,
        *,
        actor_id: str,
    ) -> SshAcceptanceRun:
        existing = self.repository.get_ssh_acceptance_run(run.run_id)
        if (run.run_id.startswith('ssh-science-')
                or any(check.check_id == 'scientific_context' for check in run.checks)
                or (existing is not None and any(check.check_id == 'scientific_context'
                    for check in existing.checks))):
            raise ValueError('scientific acceptance reports are owned by their producer')
        self.repository.put_ssh_acceptance_run(run)
        self._event(
            "ssh_acceptance.updated",
            actor_id,
            "ssh_acceptance",
            run.run_id,
            status=run.status.value,
            worker_id=run.worker_id,
        )
        return run

    @atomic_metadata
    def put_machine_preflight_run(
        self,
        run: MachinePreflightRun,
        *,
        actor_id: str,
    ) -> MachinePreflightRun:
        self.repository.put_machine_preflight_run(run)
        self._event(
            "machine_preflight.updated",
            actor_id,
            "machine",
            run.machine_id,
            run_id=run.run_id,
            stage=run.stage.value,
            status=run.status.value,
            readiness=run.readiness.value,
            warning_count=len(run.warnings),
        )
        return run

    def approve(self, approval: ApprovalRecord, *, actor_id: str) -> ApprovalRecord:
        if self.repository.get_machine(approval.machine_id) is None:
            raise KeyError(f"machine not found: {approval.machine_id}")
        self.repository.put_approval(approval)
        self._event(
            "machine.approval_updated",
            actor_id,
            "approval",
            approval.approval_id,
            machine_id=approval.machine_id,
            scope=approval.scope.value,
            approval_subject_id=approval.subject_id,
            active=approval.active,
        )
        return approval

    @solver_approval_confirmation
    def approve_solver(
        self,
        approval: SolverCompatibilityApproval,
        *,
        actor_id: str,
    ) -> SolverCompatibilityApproval:
        if self.repository.get_project_grant(approval.project_id) is None:
            raise KeyError(f"project not found: {approval.project_id}")
        if self.repository.get_profile(approval.execution_profile_id) is None:
            raise KeyError(f"execution profile not found: {approval.execution_profile_id}")
        existing = self.repository.get_solver_approval(approval.approval_id)
        expiry_only_extension = bool(
            existing is not None and existing.active and approval.active
            and existing.model_dump(exclude={"expires_at"}) == approval.model_dump(exclude={"expires_at"})
            and (approval.expires_at is None or (
                existing.expires_at is not None and approval.expires_at >= existing.expires_at
            ))
        )
        # An unchanged, retained approval may extend its lifetime without
        # issuing a new scientific environment for a retired runtime.
        if not expiry_only_extension and approval.runtime_predecessor_approval_id is not None:
            from .runtime_compatibility import same_scientific_environment
            predecessor = self.repository.get_solver_approval(approval.runtime_predecessor_approval_id)
            if (predecessor is None or not predecessor.is_active()
                    or not same_scientific_environment(predecessor, approval)
                    or not predecessor.runtime_version or not approval.runtime_version
                    or predecessor.runtime_version == approval.runtime_version):
                raise ValueError("runtime successor must bind an active, scientifically identical predecessor")
            if not self.runtime_policy.accepts_new_approval(approval.runtime_version):
                raise ValueError("runtime successor must use an explicitly accepted sealed runtime")
        if (
            not expiry_only_extension
            and approval.execution_profile_id in SEALED_COMSOL_PROFILE_IDS
            and not self.runtime_policy.accepts_new_approval(approval.runtime_version)
        ):
            raise ValueError(
                "generic COMSOL approval must bind the current sealed runtime "
                "or an explicitly accepted canary runtime"
            )
        self.repository.put_solver_approval(approval)
        self._event(
            "solver.approval_updated",
            actor_id,
            "solver_approval",
            approval.approval_id,
            project_id=approval.project_id,
            fingerprint=approval.fingerprint,
            active=approval.active,
            template_role=approval.template_role,
            template_hash_policy=approval.template_hash_policy,
            study_kinds=sorted(kind.value for kind in approval.allowed_study_kinds),
            runtime_version=approval.runtime_version,
            runtime_predecessor_approval_id=approval.runtime_predecessor_approval_id,
            runtime_equivalence_sha256=approval.runtime_equivalence_sha256,
            expiry_only_extension=expiry_only_extension,
            previous_expires_at=existing.expires_at.isoformat() if existing and existing.expires_at else None,
            expires_at=approval.expires_at.isoformat() if approval.expires_at else None,
        )
        if not expiry_only_extension:
            self._register_member_runtime_successor(approval, actor_id=actor_id)
        return approval

    def _validate_solver_request(self, request: PartitionRequest) -> None:
        self._validate_solver_policy(request)
        approval = self._resolve_solver_approval(
            project_id=request.project_id,
            execution_profile_id=request.execution_profile_id,
            allowed_solver_variants=request.allowed_solver_variants,
            item_payloads=[item.payload for item in request.items],
            hint_approval_id=request.solver_approval_id,
            strict_hint=True,
        )
        if approval is None:
            return
        request.solver_approval_id = approval.approval_id
        request.solver_compatibility_fingerprint = approval.fingerprint
        if (
            request.execution_profile_id in GENERIC_STUDY_PROFILE_IDS
            and approval.template_hash_policy == "warn_on_change"
            and request.template_sha256
            and request.template_sha256 != approval.template_sha256
        ):
            warning = (
                "template hash changed since solver-environment approval; "
                "the trusted template role remains authorized and the change is audited"
            )
            if warning not in request.planning_warnings:
                request.planning_warnings.append(warning)

    @staticmethod
    def _validate_solver_policy(request: PartitionRequest) -> None:
        if request.solver_policy == SolverPolicy.AUTO_FAST:
            if not request.allowed_solver_variants:
                raise ExecutionCompatibilityError(
                    "auto_fast_solver_not_requested",
                    "auto_fast requires at least one approved solver variant",
                    next_action="allow cuDSS, MUMPS, or both in the submission contract",
                    requires="project_owner",
                )
        elif request.solver_policy == SolverPolicy.COMPATIBILITY_MUMPS:
            if SolverVariant.MUMPS not in request.allowed_solver_variants:
                # A legacy caller may have constructed a v2 request with the
                # old default MUMPS set and then narrowed variants in-place.
                # Treat that absent, inferred policy as the new cuDSS path;
                # an explicitly declared compatibility policy remains strict.
                if not request.solver_policy_explicit and SolverVariant.CUDSS in request.allowed_solver_variants:
                    request.solver_policy = SolverPolicy.AUTO_FAST
                    return
                raise ExecutionCompatibilityError(
                    "compatibility_mumps_not_allowed",
                    "compatibility_mumps requires MUMPS in the declared solver variants",
                    next_action="add mumps to the explicit compatibility request",
                    requires="project_owner",
                )

    @staticmethod
    def _solver_approval_required(
        execution_profile_id: str,
        allowed_solver_variants: set[SolverVariant],
    ) -> bool:
        return (
            execution_profile_id in SEALED_COMSOL_PROFILE_IDS
            or SolverVariant.CUDSS in allowed_solver_variants
        )

    def _resolve_solver_approval(
        self,
        *,
        project_id: str,
        execution_profile_id: str,
        allowed_solver_variants: set[SolverVariant],
        item_payloads: list[dict],
        hint_approval_id: str | None,
        strict_hint: bool = False,
    ) -> SolverCompatibilityApproval | None:
        if not self._solver_approval_required(execution_profile_id, allowed_solver_variants):
            return None
        compatible: list[SolverCompatibilityApproval] = []
        for approval in self.repository.list_solver_approvals(
            project_id=project_id,
            active_only=True,
        ):
            if not approval.is_active():
                continue
            if approval.runtime_predecessor_approval_id:
                from .runtime_compatibility import is_registered_runtime_successor
                predecessor = self.repository.get_solver_approval(approval.runtime_predecessor_approval_id)
                if predecessor is None or not is_registered_runtime_successor(predecessor, approval):
                    continue
            if approval.execution_profile_id != execution_profile_id:
                continue
            if not allowed_solver_variants.issubset(approval.solver_variants):
                continue
            if (
                execution_profile_id in SEALED_COMSOL_PROFILE_IDS
                and not self.runtime_policy.accepts_new_approval(approval.runtime_version)
            ):
                continue
            try:
                self._validate_solver_approval_evidence(
                    approval,
                    execution_profile_id,
                    item_payloads,
                )
            except ValueError:
                continue
            compatible.append(approval)
        if not compatible:
            message = (
                "no active solver-environment approval matches this project, template hash, Study, "
                f"MeshPolicy, solver set, and sealed runtime {STABLE_RUNTIME_VERSION}"
            )
            raise ExecutionCompatibilityError("no_current_runtime_approval", message)
        by_id = {approval.approval_id: approval for approval in compatible}
        if hint_approval_id in by_id:
            return by_id[hint_approval_id]
        if hint_approval_id and strict_hint:
            raise ExecutionCompatibilityError(
                "explicit_solver_approval_incompatible",
                "the explicitly requested solver approval is not compatible with "
                "this project, template, Study, MeshPolicy, solver set, or accepted runtime; "
                "the Network will not substitute another approval",
            )
        compatible.sort(key=lambda value: (value.runtime_predecessor_approval_id is None, value.created_at, value.approval_id), reverse=True)
        return compatible[0]

    @staticmethod
    def _job_item_payloads(job: JobEnvelope) -> list[dict]:
        return [
            item["payload"]
            for unit in job.work_units
            for item in unit.payload.get("items", [])
            if isinstance(item, dict) and isinstance(item.get("payload"), dict)
        ]

    def _resolve_job_approval(self, job: JobEnvelope) -> SolverCompatibilityApproval | None:
        variants = {
            variant
            for unit in job.work_units
            for variant in unit.allowed_solver_variants
        }
        approval = self._resolve_solver_approval(
            project_id=job.project_id,
            execution_profile_id=job.execution_profile_id,
            allowed_solver_variants=variants,
            item_payloads=self._job_item_payloads(job),
            hint_approval_id=job.solver_approval_id,
            strict_hint=job.schema_version >= 2,
        )
        if approval is None:
            return None
        job.solver_approval_id = approval.approval_id
        job.solver_compatibility_fingerprint = approval.fingerprint
        for unit in job.work_units:
            unit.solver_approval_id = approval.approval_id
        return approval

    def _resolve_dispatch_approval(
        self,
        job: JobEnvelope,
        *,
        actor_id: str | None = None,
        approval_snapshot: _DispatchApprovalSnapshot | None = None,
    ) -> SolverCompatibilityApproval | None:
        """Validate approval evidence without expanding scientific item payloads.

        New Jobs persist the approval ID, fingerprint, template identity, Study
        kind, and solver variants in the operational projection. Those fields
        are sufficient for dispatch. Only legacy Jobs that predate the compact
        evidence fall back to one full aggregate read.
        """

        variants = {
            variant
            for unit in job.work_units
            for variant in unit.allowed_solver_variants
        }
        if not self._solver_approval_required(job.execution_profile_id, variants):
            return None
        try:
            return self._summary_bound_solver_approval(
                job.model_dump(mode="json"),
                variants,
                **({"approval_snapshot": approval_snapshot} if approval_snapshot is not None else {}),
            )
        except ExecutionCompatibilityError as exc:
            if exc.reason_code != "approval_evidence_incomplete":
                raise

        hydrated = self.repository.get_job(job.job_id)
        if hydrated is None:
            raise ExecutionCompatibilityError(
                "job_missing",
                "the Job disappeared while its legacy approval was being resolved",
            )
        previous_approval_id = hydrated.solver_approval_id
        previous_fingerprint = hydrated.solver_compatibility_fingerprint
        approval = self._resolve_job_approval(hydrated)
        if approval is None:
            return None

        job.solver_approval_id = approval.approval_id
        job.solver_compatibility_fingerprint = approval.fingerprint
        for unit in job.work_units:
            unit.solver_approval_id = approval.approval_id
        if (
            approval.approval_id != previous_approval_id
            or approval.fingerprint != previous_fingerprint
        ):
            resolved = approval

            def apply_approval(current: JobEnvelope) -> None:
                current.solver_approval_id = resolved.approval_id
                current.solver_compatibility_fingerprint = resolved.fingerprint
                for current_unit in current.work_units:
                    current_unit.solver_approval_id = resolved.approval_id

            self.repository.mutate_job(
                job.job_id,
                apply_approval,
                hydrate_blobs=False,
            )
            if actor_id is not None:
                self._event(
                    "job.solver_approval_reconciled",
                    actor_id,
                    "job",
                    job.job_id,
                    previous_approval_id=previous_approval_id,
                    approval_id=approval.approval_id,
                    runtime_version=approval.runtime_version,
                )
        return approval

    @staticmethod
    def _machine_owner_allows(
        approvals: list[ApprovalRecord],
        *,
        machine_id: str,
        project_id: str,
        profile_id: str,
    ) -> bool:
        now = datetime.now(timezone.utc)
        return any(
            approval.machine_id == machine_id
            and approval.is_active(now)
            and (
                (approval.scope.value == "project" and approval.subject_id == project_id)
                or (
                    approval.scope.value == "execution_profile"
                    and approval.subject_id == profile_id
                )
            )
            for approval in approvals
        )

    def _effective_person_grant(self, job):
        from .personal_runtime import effective_job_grant
        return effective_job_grant(self, job)

    def _resolve_unit_approval(
        self, job: JobEnvelope, unit: WorkUnit,
        *, approval_snapshot: _DispatchApprovalSnapshot | None = None,
    ) -> SolverCompatibilityApproval | None:
        """Honor an original Unit binding even when other Units were migrated."""
        approval_id = unit.solver_approval_id or job.solver_approval_id
        lookup_kwargs = {"approval_snapshot": approval_snapshot} if approval_snapshot is not None else {}
        if not approval_id:
            return self._resolve_dispatch_approval(job, **lookup_kwargs)
        if approval_id == job.solver_approval_id and not job.solver_compatibility_fingerprint:
            return self._resolve_dispatch_approval(job, **lookup_kwargs)
        approval = (approval_snapshot.by_id.get(approval_id) if approval_snapshot is not None
                    else self.repository.get_solver_approval(approval_id))
        if approval is None:
            raise ExecutionCompatibilityError("no_current_runtime_approval", "the Unit's bound solver approval is missing")
        # The original Unit ID is durable submission evidence. A Job-level
        # migration can change its fingerprint for other, unstarted Units.
        fingerprint = (job.solver_compatibility_fingerprint if approval_id == job.solver_approval_id
                       else approval.fingerprint)
        return self._summary_bound_solver_approval({
            "project_id": job.project_id, "execution_profile_id": job.execution_profile_id,
            "solver_approval_id": approval_id, "solver_compatibility_fingerprint": fingerprint,
            "template_sha256": job.template_sha256, "template_role": job.template_role,
            "study_kind": job.study_kind.value if job.study_kind else None,
            "recipe_kind": job.recipe_kind,
            "output_contract_sha256": job.output_contract_sha256,
        }, unit.allowed_solver_variants, **lookup_kwargs)

    def _execution_approval_for_machine(
        self, job: JobEnvelope, unit: WorkUnit, machine: MachineState,
        *, original: SolverCompatibilityApproval | None = None,
        approval_snapshot: _DispatchApprovalSnapshot | None = None,
        execution_configs: dict[str, MachineExecutionConfig] | None = None,
    ) -> SolverCompatibilityApproval | None:
        from .runtime_compatibility import select_machine_execution_approval
        original = original or self._resolve_unit_approval(
            job, unit, **({"approval_snapshot": approval_snapshot} if approval_snapshot is not None else {}),
        )
        if original is None or original.runtime_version is None:
            return original
        config = (execution_configs.get(machine.machine_id) if execution_configs is not None
                  else self.repository.get_machine_execution_config(machine.machine_id))
        if (config is None or config.runtime_version != machine.runtime_version
                or not self.runtime_policy.accepts_new_approval(machine.runtime_version)):
            return original  # Exact placement diagnostics retain the mismatch.
        return select_machine_execution_approval(
            original, (approval_snapshot.by_project.get(job.project_id, []) if approval_snapshot is not None
                       else self.repository.list_solver_approvals(project_id=job.project_id, active_only=True)),
            machine, config,
        ) or original

    def _environment_summary(
        self,
        *,
        project_id: str,
        execution_profile_id: str,
        required_capabilities: set[str],
        approval: SolverCompatibilityApproval | None,
        user_id: str | None = None,
    ) -> dict:
        profile = self.repository.get_profile(execution_profile_id)
        grant = self.repository.get_project_grant(project_id)
        if profile is None or grant is None or not grant.approved:
            return {
                "status": "awaiting_environment",
                "reason_codes": ["project_or_profile_not_enabled"],
                "runtime_version": approval.runtime_version if approval else STABLE_RUNTIME_VERSION,
                "compatible_machine_count": 0,
                "available_machine_count": 0,
                "capacity_hint": {"eligible_slots": 0, "occupied_slots": 0},
            }
        approvals = self.repository.list_approvals()
        configs = {
            config.machine_id: config
            for config in self.repository.list_machine_execution_configs()
        }
        statuses = {
            status.machine_id: status
            for status in self.repository.list_machine_operational_statuses()
        }
        required = profile.required_capabilities | required_capabilities
        runtime_version = approval.runtime_version if approval else None
        # A Job summary should describe the closest current execution candidates,
        # rather than unioning blockers from retired and owner-paused machines.
        # Full per-machine blockers remain in placement_diagnostics().
        diagnostics_by_candidate: dict[int, set[str]] = {}
        compatible = []
        available = []
        eligible_slots = 0
        occupied_slots = 0
        machines = self.repository.list_machines()
        self.repository.preload_machine_policies(machine.machine_id for machine in machines)
        for machine in machines:
            config = configs.get(machine.machine_id)
            policy = self.repository.get_policy(machine.machine_id)
            status = statuses.get(machine.machine_id)
            if config is None or not config.enabled or policy is None:
                diagnostics_by_candidate.setdefault(0, set()).add("machine_not_enabled")
                continue
            runtime_ready = True
            if runtime_version:
                from .runtime_compatibility import select_machine_execution_approval
                execution_approval = select_machine_execution_approval(
                    approval, self.repository.list_solver_approvals(project_id=project_id, active_only=True),
                    machine, config,
                ) if self.runtime_policy.accepts_new_approval(machine.runtime_version) else None
                if execution_approval is None:
                    runtime_ready = False
            capability_ready = (
                machine.platform in profile.platforms
                and required.issubset(machine.capabilities)
            )
            owner_allows = self._machine_owner_allows(
                approvals,
                machine_id=machine.machine_id,
                project_id=project_id,
                profile_id=execution_profile_id,
            )
            if user_id:
                owner_allows = owner_allows or execution_profile_id in policy.member_profile_grants.get(user_id, set())
                limit = policy.member_execution_limit
                owner_allows = owner_allows or bool(limit is not None
                    and execution_profile_id in limit.person_profiles.get(user_id, [])
                    and limit.permits(project_id, execution_profile_id,
                        runtime_version or config.runtime_version, user_id=user_id))
            online = status is not None and status.supervisor_state == SupervisorState.ONLINE
            open_for_work = policy.effective_mode() == MachineMode.OPEN
            if runtime_ready and capability_ready and owner_allows:
                compatible.append(machine)

            reasons: set[str] = set()
            if not online:
                reasons.add("supervisor_not_online")
            if not open_for_work:
                candidate_rank = 1
                reasons.add("machine_not_open")
            elif not capability_ready:
                candidate_rank = 2
                reasons.add("machine_capability_mismatch")
            else:
                candidate_rank = 4 if owner_allows else 3
                if not owner_allows:
                    reasons.add("machine_owner_approval_missing")
                if not runtime_ready:
                    reasons.add("machine_runtime_not_ready")
            diagnostics_by_candidate.setdefault(candidate_rank, set()).update(reasons)
            if not (runtime_ready and capability_ready and owner_allows and online and open_for_work):
                continue
            available.append(machine)
            cap = min(
                policy.max_concurrent_units,
                config.max_concurrent_units,
                config.target_concurrent_units,
            )
            occupied = max(0, machine.metrics.running_units)
            occupied_slots += min(cap, occupied)
            eligible_slots += max(0, cap - occupied)
        if available:
            status_value = "executable"
            reasons = [] if eligible_slots else ["capacity_temporarily_full"]
        else:
            status_value = "awaiting_environment"
            reasons = (sorted(diagnostics_by_candidate[max(diagnostics_by_candidate)])
                       if diagnostics_by_candidate else []) or ["no_compatible_machine"]
        return {
            "status": status_value,
            "reason_codes": reasons,
            "runtime_version": runtime_version,
            "compatible_machine_count": len(compatible),
            "available_machine_count": len(available),
            "capacity_hint": {
                "eligible_slots": eligible_slots,
                "occupied_slots": occupied_slots,
            },
        }

    def execution_compatibility(self, request: PartitionRequest) -> dict:
        if self.repository.get_profile(request.execution_profile_id) is None:
            raise ValueError(f"unknown execution profile: {request.execution_profile_id}")
        validate_partition_parameter_contract(request)
        try:
            approval = self._resolve_solver_approval(
                project_id=request.project_id,
                execution_profile_id=request.execution_profile_id,
                allowed_solver_variants=request.allowed_solver_variants,
                item_payloads=[item.payload for item in request.items],
                hint_approval_id=request.solver_approval_id,
                strict_hint=True,
            )
        except ExecutionCompatibilityError as exc:
            return {
                "status": "blocked_by_approval",
                "reason_codes": [exc.reason_code],
                "runtime_version": STABLE_RUNTIME_VERSION,
                "compatible_machine_count": 0,
                "available_machine_count": 0,
                "capacity_hint": {"eligible_slots": 0, "occupied_slots": 0},
            }
        return self._environment_summary(
            project_id=request.project_id,
            user_id=request.user_id,
            execution_profile_id=request.execution_profile_id,
            required_capabilities=request.required_capabilities,
            approval=approval,
        )

    def job_execution_environment(self, job: JobEnvelope) -> dict:
        snapshot = job.model_copy(deep=True)
        try:
            approval = self._resolve_job_approval(snapshot)
        except ExecutionCompatibilityError as exc:
            return {
                "status": "blocked_by_approval",
                "reason_codes": [exc.reason_code],
                "runtime_version": STABLE_RUNTIME_VERSION,
                "compatible_machine_count": 0,
                "available_machine_count": 0,
                "capacity_hint": {"eligible_slots": 0, "occupied_slots": 0},
            }
        return self._environment_summary(
            project_id=job.project_id,
            user_id=job.user_id,
            execution_profile_id=job.execution_profile_id,
            required_capabilities={
                capability
                for unit in job.work_units
                for capability in unit.required_capabilities
            },
            approval=approval,
        )

    def _summary_bound_solver_approval(
        self,
        summary: dict,
        variants: set[SolverVariant],
        *, approval_snapshot: _DispatchApprovalSnapshot | None = None,
    ) -> SolverCompatibilityApproval:
        """Validate the approval already bound to a durable Job projection."""

        approval_id = str(summary.get("solver_approval_id") or "")
        fingerprint = str(summary.get("solver_compatibility_fingerprint") or "")
        if not approval_id or not fingerprint:
            raise ExecutionCompatibilityError(
                "approval_evidence_incomplete",
                "the stored Job lacks compact solver approval evidence",
            )
        approval = (approval_snapshot.by_id.get(approval_id) if approval_snapshot is not None
                    else self.repository.get_solver_approval(approval_id))
        if approval is None or not approval.is_active():
            raise ExecutionCompatibilityError(
                "no_current_runtime_approval",
                "the solver approval bound to this Job is missing or inactive",
            )
        if approval.runtime_predecessor_approval_id:
            from .runtime_compatibility import is_registered_runtime_successor
            predecessor = (approval_snapshot.by_id.get(approval.runtime_predecessor_approval_id) if approval_snapshot is not None
                else self.repository.get_solver_approval(approval.runtime_predecessor_approval_id))
            if predecessor is None or not is_registered_runtime_successor(predecessor, approval):
                raise ExecutionCompatibilityError("no_current_runtime_approval", "the member successor's original scientific approval is missing, changed or inactive")
        if (
            approval.project_id != summary.get("project_id")
            or approval.execution_profile_id != summary.get("execution_profile_id")
            or not variants.issubset(approval.solver_variants)
            or approval.fingerprint != fingerprint
        ):
            raise ExecutionCompatibilityError(
                "explicit_solver_approval_incompatible",
                "the stored Job no longer matches its bound solver approval",
            )
        if (
            approval.execution_profile_id in SEALED_COMSOL_PROFILE_IDS
            and not self.runtime_policy.accepts_worker_runtime(approval.runtime_version)
        ):
            # This path already matched an existing active ID, fingerprint,
            # profile and solver scope. Execution may retain an accepted old
            # runtime without permitting a new legacy approval or selection.
            raise ExecutionCompatibilityError(
                "no_current_runtime_approval",
                "the Job's bound Worker runtime is not currently accepted",
            )
        if approval.execution_profile_id == SAVED_READOUT_PROFILE_ID:
            try:
                registered = saved_readout_source_contract(
                    summary.get("template_role"), summary.get("template_sha256"))
            except ValueError:
                registered = None
            if (registered is None or summary.get("template_sha256") != approval.template_sha256
                    or summary.get("template_role") != approval.template_role
                    or summary.get("study_kind") is not None
                    or summary.get("recipe_kind") != SAVED_READOUT_PROFILE_ID
                    or summary.get("output_contract_sha256") != registered["output_contract_sha256"]
                    or approval.allowed_study_kinds or approval.mesh_policy is not None):
                raise ExecutionCompatibilityError(
                    "explicit_solver_approval_incompatible",
                    "the stored saved readout Job differs from its exact approved source",
                )
        if approval.execution_profile_id == TEMPLATE_BUILD_PROFILE_ID:
            if (summary.get("template_sha256") != approval.template_sha256
                    or summary.get("template_role") != approval.template_role
                    or summary.get("study_kind") is not None
                    or approval.allowed_study_kinds):
                raise ExecutionCompatibilityError(
                    "explicit_solver_approval_incompatible",
                    "the stored template construction Job differs from its exact approved source",
                )
        if approval.execution_profile_id in GENERIC_STUDY_PROFILE_IDS:
            template_hash = str(summary.get("template_sha256") or "")
            if (
                approval.template_hash_policy == "exact"
                and template_hash != approval.template_sha256
            ):
                raise ExecutionCompatibilityError(
                    "explicit_solver_approval_incompatible",
                    "the stored Job template hash differs from its bound solver approval",
                )
            if str(summary.get("template_role") or "") != str(approval.template_role or ""):
                raise ExecutionCompatibilityError(
                    "explicit_solver_approval_incompatible",
                    "the stored Job template role differs from its bound solver approval",
                )
            allowed_study_kinds = {kind.value for kind in approval.allowed_study_kinds}
            if str(summary.get("study_kind") or "") not in allowed_study_kinds:
                raise ExecutionCompatibilityError(
                    "explicit_solver_approval_incompatible",
                    "the stored Job Study kind is outside its bound solver approval",
                )
        return approval

    def job_summary_environment(self, summary: dict) -> dict:
        variants = {
            SolverVariant(value)
            for unit in summary.get("work_units", [])
            for value in unit.get("allowed_solver_variants", [])
        }
        profile_id = summary["execution_profile_id"]
        approval = None
        if self._solver_approval_required(profile_id, variants):
            try:
                approval = self._summary_bound_solver_approval(
                    summary,
                    variants,
                )
            except ExecutionCompatibilityError as exc:
                return {
                    "status": "blocked_by_approval",
                    "reason_codes": [exc.reason_code],
                    "runtime_version": STABLE_RUNTIME_VERSION,
                    "compatible_machine_count": 0,
                    "available_machine_count": 0,
                    "capacity_hint": {"eligible_slots": 0, "occupied_slots": 0},
                }
        return self._environment_summary(
            project_id=summary["project_id"],
            user_id=summary.get("user_id"),
            execution_profile_id=profile_id,
            required_capabilities={
                capability
                for unit in summary.get("work_units", [])
                for capability in unit.get("required_capabilities", [])
            },
            approval=approval,
        )

    @staticmethod
    def _validate_solver_approval_evidence(
        approval: SolverCompatibilityApproval,
        execution_profile_id: str,
        item_payloads: list[dict],
    ) -> None:
        """Bind new recipe requests to the reviewed template and MeshPolicy."""
        if execution_profile_id == SAVED_READOUT_PROFILE_ID:
            if len(item_payloads) != 1:
                raise ValueError("saved readout approval requires exactly one fixed diagnostic")
            registered = saved_readout_contract(item_payloads[0].get("diagnostic", {}).get("name"))
            if (len(item_payloads) != 1 or approval.template_hash_policy != "exact"
                    or approval.allowed_study_kinds or approval.mesh_policy is not None
                    or approval.template_role != registered["template_role"]
                    or approval.template_sha256 != registered["template_sha256"]
                    or any(payload.get("template_role") != approval.template_role
                           or payload.get("template_sha256") != approval.template_sha256
                           or payload.get("output_contract_sha256") != registered["output_contract_sha256"]
                           or "mesh_policy" in payload or "study" in payload
                           for payload in item_payloads)):
                raise ValueError("saved readout approval does not bind its exact zero-run source")
            return
        if execution_profile_id == TEMPLATE_BUILD_PROFILE_ID:
            if len(item_payloads) != 1:
                raise ValueError("template construction approval requires one fixed preset")
            construction = item_payloads[0].get("construction")
            if (not isinstance(construction, dict)
                    or set(construction) != {"schema_version", "preset"}
                    or type(construction["schema_version"]) is not int
                    or construction["schema_version"] != 1):
                raise ValueError("template construction approval requires a registered preset")
            registered = template_build_preset_contract(construction["preset"])
            if (approval.template_hash_policy != "exact"
                    or approval.allowed_study_kinds
                    or approval.template_role != registered["template_role"]
                    or approval.template_sha256 != registered["template_sha256"]
                    or approval.mesh_policy is None
                    or approval.mesh_policy.model_dump(mode="json", exclude_none=True) != TEMPLATE_BUILD_MESH_POLICY
                    or any(payload.get("template_role") != approval.template_role
                           or payload.get("template_sha256") != approval.template_sha256
                           or payload.get("mesh_policy") != TEMPLATE_BUILD_MESH_POLICY
                           or payload.get("output_contract_sha256") != registered["output_contract_sha256"]
                           for payload in item_payloads)):
                raise ValueError("template construction approval does not bind its exact source and mesh")
            return
        structured_mesh_profiles = {
            "workbench-comsol-eigen-v3",
            "workbench-comsol-eigen-v4",
            "workbench-comsol-frequency-v2",
            "workbench-comsol-study-v1",
            "workbench-comsol-study-v2",
        }
        if execution_profile_id not in structured_mesh_profiles:
            return
        template_hashes = {
            str(payload.get("template_sha256", ""))
            for payload in item_payloads
        }
        if (
            execution_profile_id not in {"workbench-comsol-study-v1", "workbench-comsol-study-v2"}
            or approval.template_hash_policy == "exact"
        ) and template_hashes != {approval.template_sha256}:
            raise ValueError("solver approval template hash does not match the request")
        if execution_profile_id in {"workbench-comsol-study-v1", "workbench-comsol-study-v2"}:
            template_roles = {str(payload.get("template_role", "")) for payload in item_payloads}
            study_kinds = {
                str(payload.get("study", {}).get("kind", ""))
                for payload in item_payloads
                if isinstance(payload.get("study"), dict)
            }
            if template_roles != {approval.template_role}:
                raise ValueError("solver approval template role does not match the request")
            if not study_kinds or not study_kinds.issubset(
                {kind.value for kind in approval.allowed_study_kinds}
            ):
                raise ValueError("solver approval does not cover the requested Study kind")
        raw_policies = [
            (
                payload.get("study", {}).get("mesh_policy")
                if execution_profile_id in {"workbench-comsol-study-v1", "workbench-comsol-study-v2"}
                and isinstance(payload.get("study"), dict)
                else payload.get("recipe_config", {}).get("mesh_policy")
            )
            for payload in item_payloads
            if (
                execution_profile_id in {"workbench-comsol-study-v1", "workbench-comsol-study-v2"}
                and isinstance(payload.get("study"), dict)
            ) or isinstance(payload.get("recipe_config"), dict)
        ]
        if len(raw_policies) != len(item_payloads):
            raise ValueError("structured COMSOL request lacks MeshPolicy evidence")
        try:
            policies = [SolverMeshPolicy.model_validate(value) for value in raw_policies]
        except Exception as exc:
            raise ValueError("structured COMSOL request has invalid MeshPolicy evidence") from exc
        if approval.mesh_policy is None or any(policy != approval.mesh_policy for policy in policies):
            raise ValueError("solver approval MeshPolicy does not match the request")

    @atomic_metadata
    def plan_partition(self, request: PartitionRequest, *, actor_id: str) -> PartitionPlan:
        from .personal_runtime import authorize_request, execution_binding
        authorize_request(self, request, actor_id=actor_id)
        execution_binding(self, request)
        profile = self.repository.get_profile(request.execution_profile_id)
        if profile is None:
            raise ValueError(f"unknown execution profile: {request.execution_profile_id}")
        policy = self.repository.get_feature_settings().resource_policies.get(
            request.execution_profile_id
        )
        resolved = resolve_resources(
            profile=profile,
            schema_version=request.schema_version,
            requested=request.resources,
            policy=policy,
        )
        request.resources = resolved.resources
        request.resolved_resources = resolved
        validate_partition_parameter_contract(request)
        hinted_approval_id = request.solver_approval_id
        self._validate_solver_request(request)
        plan = create_partition_plan(request, resource_policy=policy or default_resource_policy(profile))
        existing = self.repository.get_partition_plan(plan.plan_id)
        if existing is not None:
            if (existing.request.user_id, existing.request.project_id, existing.request.origin_submitter_id,
                    existing.request.origin_adapter_id, existing.request.execution_profile_id) != (
                    request.user_id, request.project_id, request.origin_submitter_id,
                    request.origin_adapter_id, request.execution_profile_id):
                raise ExecutionCompatibilityError("submission_identity_conflict", "existing plan belongs to a different member, project or origin")
            return existing
        self.repository.put_partition_plan(plan)
        if hinted_approval_id != request.solver_approval_id:
            self._event(
                "solver.approval_resolved",
                actor_id,
                "partition_plan",
                plan.plan_id,
                project_id=request.project_id,
                replaced_hint=bool(hinted_approval_id),
                approval_id=request.solver_approval_id,
                runtime_version=STABLE_RUNTIME_VERSION,
            )
        self._event(
            "partition_plan.created",
            actor_id,
            "partition_plan",
            plan.plan_id,
            project_id=request.project_id,
            atomic_items=plan.atomic_item_count,
            work_units=len(plan.work_units),
            study_kind=request.study_kind.value if request.study_kind else None,
            template_role=request.template_role,
            template_sha256=request.template_sha256,
            output_contract_sha256=request.output_contract_sha256,
            estimated_output_bytes=request.estimated_output_bytes,
            warnings=list(request.planning_warnings),
            resource_source=request.resolved_resources.source,
            resource_policy_revision=resolved.policy_revision,
            resources=request.resources.model_dump(mode="json"),
            disk_estimate=request.disk_estimate.model_dump(mode="json") if request.disk_estimate else None,
            unit_disk_mb=[unit.resources.disk_mb for unit in plan.work_units] if request.disk_estimate else None,
        )
        return plan

    @atomic_metadata
    def confirm_partition(self, plan_id: str, *, actor_id: str) -> JobEnvelope:
        plan = self.repository.get_partition_plan(plan_id)
        if plan is None:
            raise KeyError(f"partition plan not found: {plan_id}")
        validate_partition_parameter_contract(plan.request)
        self._validate_solver_request(plan.request)
        confirmed = confirm_partition_plan(plan)
        self.repository.put_partition_plan(confirmed)
        job = self.submit(job_from_confirmed_plan(confirmed), actor_id=actor_id)
        self._event(
            "partition_plan.confirmed",
            actor_id,
            "partition_plan",
            plan_id,
            job_id=job.job_id,
        )
        return job

    @atomic_metadata
    def submit(self, job: JobEnvelope, *, actor_id: str) -> JobEnvelope:
        from .dispatch_policy import requested_task_priority
        requested_priority = requested_task_priority(job)
        terminal_states = {
            JobStatus.COMPLETED,
            JobStatus.FAILED_TERMINAL,
            JobStatus.CANCELLED,
        }

        def same_execution(existing: JobEnvelope) -> bool:
            if (existing.user_id, existing.project_id, existing.origin_submitter_id,
                    existing.origin_adapter_id, existing.execution_profile_id) != (
                    job.user_id, job.project_id, job.origin_submitter_id,
                    job.origin_adapter_id, job.execution_profile_id):
                raise ExecutionCompatibilityError("submission_identity_conflict",
                    "existing Job hash or ID belongs to a different member, project or origin")
            return (
                existing.solver_approval_id == job.solver_approval_id
                and existing.solver_compatibility_fingerprint
                == job.solver_compatibility_fingerprint
            )

        existing = self.repository.get_job_by_hash(job.request_hash)
        if existing is not None:
            same_execution(existing)
        if existing and same_execution(existing) and existing.status not in terminal_states:
            self._event("job.idempotent_reuse", actor_id, "job", existing.job_id, request_hash=job.request_hash)
            return existing
        if existing:
            # The scientific request hash can remain stable while a new
            # solver approval/runtime is canaried. SQLite keeps this column
            # unique, so derive a durable Job identity for the new execution
            # environment instead of mutating or reusing the old Job.
            job.request_hash = sha256_value({
                "base_request_hash": job.request_hash,
                "solver_approval_id": job.solver_approval_id,
                "solver_compatibility_fingerprint": job.solver_compatibility_fingerprint,
            })
            existing = self.repository.get_job_by_hash(job.request_hash)
            if existing is not None:
                same_execution(existing)
            if existing and same_execution(existing) and existing.status not in terminal_states:
                self._event("job.idempotent_reuse", actor_id, "job", existing.job_id, request_hash=job.request_hash)
                return existing

        # A confirmed plan normally supplies a deterministic Job ID.  A
        # previous attempt may already occupy that ID after being reconciled
        # to a different approval/runtime.  Keep terminal history immutable
        # and create a fresh durable identity instead of surfacing a database
        # revision conflict from put_job().
        existing_by_id = self.repository.get_job(job.job_id)
        if existing_by_id is not None:
            if same_execution(existing_by_id) and existing_by_id.status not in terminal_states:
                self._event(
                    "job.idempotent_reuse",
                    actor_id,
                    "job",
                    existing_by_id.job_id,
                    request_hash=job.request_hash,
                )
                return existing_by_id
            original_job_id = job.job_id
            supersede_nonce = secrets.token_hex(8)
            derived_identity = sha256_value({
                'original_job_id': original_job_id,
                'request_hash': job.request_hash,
                'solver_approval_id': job.solver_approval_id,
                'solver_compatibility_fingerprint': job.solver_compatibility_fingerprint,
                'supersede_nonce': supersede_nonce,
            })
            job.job_id = f"job-{derived_identity[:24]}"
            job.request_hash = sha256_value({
                "base_request_hash": job.request_hash,
                "superseded_job_id": original_job_id,
                "supersede_nonce": supersede_nonce,
            })
            self._event(
                "job.superseded_identity",
                actor_id,
                "job",
                job.job_id,
                superseded_job_id=original_job_id,
                request_hash=job.request_hash,
                solver_approval_id=job.solver_approval_id,
            )

        legacy_acceptance_probe = (
            job.execution_profile_id == "project-worker-v1"
            and job.record_class == "acceptance"
            and actor_id == "retry-migration-auditor"
        )
        if job.execution_profile_id == "project-worker-v1" and not legacy_acceptance_probe:
            raise ExecutionCompatibilityError(
                "legacy_profile_read_only",
                "project-worker-v1 remains available for existing Jobs but rejects new submissions",
            )
        adapter = self.repository.get_origin_adapter(job.origin_adapter_id)
        if adapter is None:
            raise ExecutionCompatibilityError(
                "origin_adapter_not_registered",
                f"origin adapter is not registered: {job.origin_adapter_id}",
            )
        if not adapter.active or not adapter.accepts_new_submissions:
            raise ExecutionCompatibilityError(
                "origin_adapter_read_only",
                f"origin adapter does not accept new submissions: {job.origin_adapter_id}",
            )
        if (
            adapter.allowed_profile_ids
            and job.execution_profile_id not in adapter.allowed_profile_ids
            and not legacy_acceptance_probe
        ):
            raise ExecutionCompatibilityError(
                "origin_adapter_profile_not_allowed",
                "origin adapter is not registered for the requested Profile",
            )

        profile = self.repository.get_profile(job.execution_profile_id)
        if profile is None:
            raise ValueError(f"unknown execution profile: {job.execution_profile_id}")
        settings = self.repository.get_feature_settings()
        policy = settings.resource_policies.get(
            job.execution_profile_id
        )
        for unit in job.work_units:
            if unit.resolved_resources is None:
                resolved = resolve_resources(
                    profile=profile,
                    schema_version=1,
                    requested=unit.resources,
                    policy=policy,
                )
                unit.resources = resolved.resources
                unit.resolved_resources = resolved
        validate_job_parameter_contract(job)
        self._resolve_job_approval(job)
        # Keep the wire-level retry policy and each unit's immutable attempt
        # ledger in sync.  A caller may still choose a stricter per-unit cap,
        # but can never silently exceed the envelope's bound.
        for unit in job.work_units:
            unit.max_attempts = min(unit.max_attempts, job.retry_policy.max_attempts)
        from .personal_runtime import authorize_request
        grant = authorize_request(self, job, queued_units=len(job.work_units), actor_id=actor_id)
        from .dispatch_policy import SchedulingPolicy, resolve_submission_priority, task_priority_ceiling
        scheduling = settings.scheduling_policy or SchedulingPolicy()
        parallel_estimate = self._parallel_batch_estimate(job, policy=scheduling)
        ceiling = task_priority_ceiling(scheduling, job, grant, parallel_estimate=parallel_estimate)
        job.priority, job.priority_source, batch_size = resolve_submission_priority(
            scheduling, job, ceiling=ceiling, parallel_estimate=parallel_estimate)
        job.priority_explicit = requested_priority is not None
        job.effective_priority = job.priority
        job.duration_estimate_complete = batch_size['estimate_complete']
        if grant is None:
            job.status = JobStatus.AWAITING_APPROVAL
        elif grant.status != ProjectStatus.ACTIVE or job.execution_profile_id not in grant.allowed_profiles:
            job.status = JobStatus.AWAITING_APPROVAL
        else:
            if job.priority > ceiling:
                raise ExecutionCompatibilityError(
                    "project_priority_ceiling_exceeded",
                    f"requested priority {job.priority} exceeds task ceiling {ceiling}",
                )
            queued_units = sum(
                1
                for existing_job in self.repository.list_operational_jobs(
                    statuses={JobStatus.QUEUED, JobStatus.RUNNING},
                    project_id=job.project_id,
                )
                for unit in existing_job.work_units
                if unit.status == WorkUnitStatus.QUEUED
            )
            if queued_units + len(job.work_units) > grant.max_queued_units:
                raise ExecutionCompatibilityError(
                    "project_queued_quota_exceeded",
                    "submission would exceed the project's queued WorkUnit quota",
                )
            job.effective_priority = job.priority
            job.priority_ceiling_snapshot = ceiling
            job.status = JobStatus.QUEUED

        self.repository.put_job(job)
        priority_details = {"requested_priority": requested_priority, "priority": job.priority,
                             "effective_priority": job.effective_priority,
                             "priority_ceiling": ceiling,
                             "project_priority_ceiling": grant.priority_ceiling if grant else None,
                             "priority_source": job.priority_source,
                             "short_compute": batch_size,
                             "central_priority_rule_applied": requested_priority is None}
        self._event("job.submitted", actor_id, "job", job.job_id, status=job.status.value, **priority_details)
        return job

    @settle_after
    def cancel(self, job_id: str, *, actor_id: str, reason: str = "") -> JobEnvelope:
        snapshot = self.repository.get_operational_job(job_id)
        if snapshot is None:
            raise KeyError(f"job not found: {job_id}")
        active_attempt_states = {
            "assigned",
            "submitting",
            "running",
            "reconcile_pending",
            "uncertain",
            "collecting",
        }

        def needs_cancellation(unit: WorkUnit) -> bool:
            if unit.status == WorkUnitStatus.COMPLETED:
                return False
            return bool(
                unit.status not in {WorkUnitStatus.FAILED_TERMINAL, WorkUnitStatus.CANCELLED}
                or any(attempt.state in active_attempt_states for attempt in unit.attempts)
            )

        if snapshot.status == JobStatus.COMPLETED or not any(
            needs_cancellation(unit) for unit in snapshot.work_units
        ):
            return self.repository.get_job(job_id) or snapshot

        changed = False

        def apply_cancel(job: JobEnvelope) -> None:
            nonlocal changed
            changed = False
            if job.status == JobStatus.COMPLETED:
                return
            now = datetime.now(timezone.utc)
            targets = [unit for unit in job.work_units if needs_cancellation(unit)]
            if not targets:
                return
            job.status = JobStatus.CANCELLED
            for unit in targets:
                unit.status = WorkUnitStatus.CANCELLED
                unit.failure_reason = reason or "job cancelled"
                for attempt in unit.attempts:
                    if attempt.state in active_attempt_states:
                        attempt.cancel_requested_at = now
                        attempt.state = "cancel_pending" if attempt.external_run_id else "cancelled"
                        attempt.finished_at = None if attempt.external_run_id else now
                        attempt.failure_reason = unit.failure_reason
            changed = True

        updated = self.repository.mutate_job(job_id, apply_cancel, hydrate_blobs=False)
        if changed:
            self._event("job.cancelled", actor_id, "job", job_id, reason=reason)
        # Preserve the historical response contract without rewriting the large
        # immutable scientific payload as part of the cancellation transaction.
        return self.repository.get_job(job_id) or updated

    @settle_after
    def cancel_unit(
        self,
        job_id: str,
        work_unit_id: str,
        *,
        actor_id: str,
        reason: str = "",
    ) -> JobEnvelope:
        """Cancel exactly one unit while leaving unrelated units untouched."""
        snapshot = self.repository.get_operational_job(job_id)
        if snapshot is None:
            raise KeyError(f"job not found: {job_id}")
        snapshot_unit = next(
            (item for item in snapshot.work_units if item.work_unit_id == work_unit_id),
            None,
        )
        if snapshot_unit is None:
            raise KeyError(f"work unit not found: {work_unit_id}")
        active_attempt_states = {
            "assigned",
            "submitting",
            "running",
            "reconcile_pending",
            "uncertain",
            "collecting",
        }
        terminal = {WorkUnitStatus.COMPLETED, WorkUnitStatus.FAILED_TERMINAL}
        if snapshot_unit.status in terminal or (
            snapshot_unit.status == WorkUnitStatus.CANCELLED
            and not any(
                attempt.state in active_attempt_states for attempt in snapshot_unit.attempts
            )
        ):
            return self.repository.get_job(job_id) or snapshot

        changed = False
        cancellation_reason = reason or "work unit cancelled"

        def apply_cancel(job: JobEnvelope) -> None:
            nonlocal changed
            changed = False
            unit = next(
                (item for item in job.work_units if item.work_unit_id == work_unit_id),
                None,
            )
            if unit is None:
                raise KeyError(f"work unit not found: {work_unit_id}")
            if unit.status in terminal or (
                unit.status == WorkUnitStatus.CANCELLED
                and not any(attempt.state in active_attempt_states for attempt in unit.attempts)
            ):
                return
            now = datetime.now(timezone.utc)
            unit.status = WorkUnitStatus.CANCELLED
            unit.failure_reason = cancellation_reason
            for attempt in unit.attempts:
                if attempt.state in active_attempt_states:
                    attempt.cancel_requested_at = now
                    attempt.state = "cancel_pending" if attempt.external_run_id else "cancelled"
                    attempt.finished_at = None if attempt.external_run_id else now
                    attempt.failure_reason = cancellation_reason
            remaining = [item.status for item in job.work_units]
            if all(
                status in {
                    WorkUnitStatus.COMPLETED,
                    WorkUnitStatus.CANCELLED,
                    WorkUnitStatus.FAILED_TERMINAL,
                }
                for status in remaining
            ):
                job.status = JobStatus.CANCELLED
            changed = True

        updated = self.repository.mutate_job(job_id, apply_cancel, hydrate_blobs=False)
        if changed:
            self._event(
                "work_unit.cancelled",
                actor_id,
                "work_unit",
                work_unit_id,
                job_id=job_id,
                reason=cancellation_reason,
            )
        return self.repository.get_job(job_id) or updated

    def _dispatch_order(
        self,
        job: JobEnvelope,
        now: datetime,
        *,
        project_usage_seconds: float | None = None,
        user_usage_seconds: float | None = None,
    ) -> tuple:
        dispatch_priority = self._effective_dispatch_priority(job, now)
        return (
            -dispatch_priority,
            (
                project_usage_seconds
                if project_usage_seconds is not None
                else self.repository.recent_project_usage_seconds(job.project_id)
            ),
            (
                user_usage_seconds
                if user_usage_seconds is not None
                else self.repository.recent_usage_seconds(job.user_id)
            ),
            job.last_scheduled_at or datetime.min.replace(tzinfo=timezone.utc),
            job.created_at,
            job.job_id,
        )

    def _base_dispatch_priority(self, job: JobEnvelope, policy) -> int:
        # Acceptance or an explicit operator mutation owns the base rank.
        # Later changes to project defaults cannot re-rank accepted Jobs.
        return job.effective_priority if job.effective_priority is not None else job.priority

    def _effective_dispatch_priority(self, job: JobEnvelope, now: datetime, *, policy=None) -> int:
        """Return the priority rank shared by direct and standby dispatch."""

        wait_seconds = max((now - (job.last_scheduled_at or job.created_at)).total_seconds(), 0.0)
        # Aging changes the effective scheduling rank, so sustained high
        # priority traffic cannot starve an older low-priority Job forever.
        aging_credit = min(int(wait_seconds // 1800), 200)
        from .dispatch_policy import policy_for
        return self._base_dispatch_priority(job, policy or policy_for(self.repository)) + aging_credit

    def _scheduling_priority(self, job: JobEnvelope, now: datetime, policy) -> int:
        if policy.strategy == "balanced":
            return self._effective_dispatch_priority(job, now, policy=policy)
        # Small-batch/throughput policy uses explicit priority bands, then the
        # common bounded waiting guard. Aging must not silently turn a 31-minute
        # large Job into a higher-priority Job than a new small probe in the same
        # operator-selected band. Balanced keeps its legacy effective rank.
        return self._base_dispatch_priority(job, policy)

    def _parallel_batch_estimate(self, job: JobEnvelope, *, remaining=False, now=None,
                                 policy=None, capacity_snapshot=None):
        from .dispatch_policy import policy_for
        policy = policy or policy_for(self.repository)
        if policy.small_batch_max_parallel_seconds is None:
            return None
        from .small_batch_estimate import estimate_parallel_batch, build_parallel_batch_snapshot
        from functools import partial
        units = ([unit for unit in job.work_units
                  if unit.status not in {WorkUnitStatus.COMPLETED, WorkUnitStatus.CANCELLED, WorkUnitStatus.FAILED_TERMINAL}]
                 if remaining else job.work_units)
        # Reject obviously long batches before the per-Unit placement simulation.
        # This bound deliberately overestimates capacity, so it cannot exclude
        # a batch that could actually finish inside the configured threshold.
        declared = (job.duration_estimate_complete if job.duration_estimate_complete is not None else
                    all('expected_duration_s' in unit.model_fields_set for unit in units))
        if not units or not declared:
            return estimate_parallel_batch(capacity_snapshot or self.repository, job, units=units, now=now)
        def too_long(reason):
            return {'estimated_parallel_seconds': None, 'compatible_slots': 0,
                    'estimate_complete': False, 'reason': reason, 'basis': 'duration/capacity lower bound'}
        if max(unit.expected_duration_s for unit in units) > policy.small_batch_max_parallel_seconds:
            return too_long('indivisible_unit_exceeds_parallel_limit')
        capacity = capacity_snapshot or build_parallel_batch_snapshot(
            self.repository, now=now,
            resource_calibrator=partial(self._memory_calibrated_unit, history_cache={}))
        grant = capacity.grants.get(job.project_id)
        upper = sum(min(owner.max_concurrent_units, config.max_concurrent_units)
                    for machine_id, owner in capacity.policies.items()
                    if (config := capacity.configs.get(machine_id)) is not None and config.enabled
                    and owner.effective_mode().value == 'open')
        if grant is not None:
            upper = min(upper, grant.max_running_units)
        if upper > 0 and sum(unit.expected_duration_s for unit in units) > upper * policy.small_batch_max_parallel_seconds:
            return too_long('total_work_exceeds_maximum_capacity_time_budget')
        return estimate_parallel_batch(capacity, job, units=units, now=now)

    @io_priority.foreground(quiet_after=.25)
    def _sort_dispatch_jobs(self, jobs: list[JobEnvelope], now: datetime, *, policy=None) -> None:
        from .dispatch_policy import policy_for, dispatch_order
        policy = policy or policy_for(self.repository)
        usage = self.repository.recent_resource_usage(hours=policy.history_window_hours, now=now)
        estimates = {}
        if policy.small_batch_max_parallel_seconds is not None and jobs:
            from .small_batch_estimate import build_parallel_batch_snapshot
            from functools import partial
            capacity = build_parallel_batch_snapshot(
                self.repository, now=now,
                resource_calibrator=partial(self._memory_calibrated_unit, history_cache={}))
            estimates = {job.job_id: self._parallel_batch_estimate(
                job, remaining=True, now=now, policy=policy, capacity_snapshot=capacity) for job in jobs}
        from .personal_runtime import policy_store
        store = policy_store(self)
        person_policies = {user_id: store.get_policy(user_id) for user_id in {job.user_id for job in jobs}}
        credits = self._compute_credits if hasattr(self, "_compute_credits") else None
        metered = bool(credits and credits.settings()["metering_enabled"])
        balances = {uid: credits.balance(uid) for uid, value in person_policies.items() if metered and value}
        def order(job):
            legacy = dispatch_order(job, now=now, policy=policy,
                priority=self._scheduling_priority(job, now, policy),
                project_usage=usage["projects"].get(job.project_id),
                user_usage=usage["users"].get(job.user_id), parallel_estimate=estimates.get(job.job_id))
            personal = person_policies[job.user_id]
            if personal is None:
                return (0, *legacy)
            balance = balances.get(job.user_id, {})
            idle_only = metered and personal.quota_mode == "metered" and not (
                balance.get("available_cpu_core_hours", 0) > 0 or balance.get("available_gpu_device_hours", 0) > 0)
            person_usage = usage["users"].get(job.user_id) or {}
            return (int(idle_only), legacy[0], person_usage.get("core_seconds", 0),
                    person_usage.get("gpu_seconds", 0), *legacy[1:])
        jobs.sort(key=order)

    def project_concurrency_snapshot(
        self,
        project_id: str,
        *,
        jobs: list[JobEnvelope] | None = None,
        reservations: list[DispatchReservation] | None = None,
    ) -> dict[str, int | str | None]:
        """Return the project-wide limit enforced by both dispatch paths."""

        return self.project_concurrency_snapshots(
            {project_id}, jobs=jobs, reservations=reservations
        )[project_id]

    def project_concurrency_snapshots(
        self,
        project_ids: set[str],
        *,
        jobs: list[JobEnvelope] | None = None,
        reservations: list[DispatchReservation] | None = None,
    ) -> dict[str, dict[str, int | str | None]]:
        """Compute project concurrency from one immutable operational sample."""
        if not project_ids:
            return {}
        if jobs is None and reservations is None:
            facts = self.repository.project_concurrency_facts(project_ids)
            return {project_id: {
                "project_id": project_id,
                "active_units": counts["active_units"],
                "prepared_units": counts["prepared_units"],
                "used_units": counts["active_units"],
                "max_running_units": counts["max_running_units"],
                "available_units": max(0, counts["max_running_units"] - counts["active_units"])
                    if counts["max_running_units"] is not None else None,
            } for project_id, counts in facts.items()}
        active_jobs = jobs if jobs is not None else self.repository.list_operational_jobs(
            statuses={JobStatus.QUEUED, JobStatus.RUNNING},
        )
        active_reservations = (
            reservations
            if reservations is not None
            else self.repository.list_dispatch_reservations(active_only=True)
        )
        project_by_job = {job.job_id: job.project_id for job in active_jobs}
        active_counts = {project_id: 0 for project_id in project_ids}
        prepared_counts = {project_id: 0 for project_id in project_ids}
        for job in active_jobs:
            if job.project_id not in active_counts:
                continue
            active_counts[job.project_id] += sum(
                unit.status in {
                    WorkUnitStatus.ASSIGNED,
                    WorkUnitStatus.RUNNING,
                    WorkUnitStatus.RECONCILE_PENDING,
                }
                for unit in job.work_units
            )
        for reservation in active_reservations:
            project_id = project_by_job.get(reservation.job_id)
            if (
                project_id in prepared_counts
                and reservation.state in {"preparing", "prepared", "activating"}
            ):
                prepared_counts[project_id] += 1
        grants = {
            grant.project_id: grant for grant in self.repository.list_project_grants()
            if grant.project_id in project_ids
        }
        snapshots: dict[str, dict[str, int | str | None]] = {}
        for project_id in project_ids:
            active_units = active_counts[project_id]
            prepared_units = prepared_counts[project_id]
            maximum = grants.get(project_id).max_running_units if project_id in grants else None
            snapshots[project_id] = {
                "project_id": project_id,
                "active_units": active_units,
                "prepared_units": prepared_units,
                "used_units": active_units,
                "max_running_units": maximum,
                "available_units": (
                    max(0, maximum - active_units) if maximum is not None else None
                ),
            }
        return snapshots

    def placement_diagnostics(self, job_id: str) -> dict:
        """Return member-safe, dispatch-equivalent diagnostics for every Unit."""

        selected = self.repository.get_operational_job(job_id)
        if selected is None:
            raise KeyError(f"job not found: {job_id}")
        generated_at = datetime.now(timezone.utc)
        all_jobs = self.repository.list_operational_jobs(
            statuses={JobStatus.QUEUED, JobStatus.RUNNING},
        )
        schedulable_jobs = [
            job for job in all_jobs if job.status in {JobStatus.QUEUED, JobStatus.RUNNING}
        ]
        self._sort_dispatch_jobs(schedulable_jobs, generated_at)
        queue_positions: dict[tuple[str, str], int] = {}
        position = 0
        for job in schedulable_jobs:
            for unit in job.work_units:
                if unit.status == WorkUnitStatus.QUEUED:
                    position += 1
                    queue_positions[(job.job_id, unit.work_unit_id)] = position

        active_by_machine: dict[str, list[WorkUnit]] = {}
        active_by_machine_profile: dict[tuple[str, str], list[WorkUnit]] = {}
        for job in all_jobs:
            for unit in job.work_units:
                if unit.assigned_machine_id and unit.status in {
                    WorkUnitStatus.ASSIGNED,
                    WorkUnitStatus.RUNNING,
                    WorkUnitStatus.RECONCILE_PENDING,
                }:
                    active_by_machine.setdefault(unit.assigned_machine_id, []).append(unit)
                    active_by_machine_profile.setdefault(
                        (unit.assigned_machine_id, job.execution_profile_id), []
                    ).append(unit)

        snapshot = selected.model_copy(deep=True)
        approval_snapshot = _DispatchApprovalSnapshot(self.repository)
        approval = None
        approval_error: ExecutionCompatibilityError | None = None
        try:
            approval = self._resolve_dispatch_approval(snapshot, approval_snapshot=approval_snapshot)
        except ExecutionCompatibilityError as exc:
            approval_error = exc
        grant = self._effective_person_grant(snapshot)
        profile = self.repository.get_profile(snapshot.execution_profile_id)
        approvals = self.repository.list_approvals()
        configs = {
            item.machine_id: item for item in self.repository.list_machine_execution_configs()
        }
        statuses = {
            item.machine_id: item for item in self.repository.list_machine_operational_statuses()
        }
        machines = self.repository.list_machines()
        policies = {machine.machine_id: self.repository.get_policy(machine.machine_id) for machine in machines}
        pressure_settings = self.repository.get_feature_settings().pressure_policy
        units_payload = []
        reservations = {
            (item.job_id, item.work_unit_id): item
            for item in self.repository.list_dispatch_reservations(active_only=True)
        }
        project_concurrency = self.project_concurrency_snapshot(
            snapshot.project_id,
            jobs=all_jobs,
            reservations=list(reservations.values()),
        )
        project_concurrency_used = int(project_concurrency["used_units"] or 0)
        memory_history: dict[tuple[str, str], list[JobEnvelope]] = {}
        for unit in snapshot.work_units:
            evaluations: list[MachinePlacementEvaluation] = []
            dispatch_ready = self._dispatch_ready(unit, generated_at)
            try:
                original_approval = self._resolve_unit_approval(snapshot, unit, approval_snapshot=approval_snapshot)
                approval_error = None
            except ExecutionCompatibilityError as exc:
                original_approval = None
                approval_error = exc
            if unit.status == WorkUnitStatus.QUEUED and dispatch_ready and grant is not None and profile is not None:
                for machine in machines:
                    policy = policies.get(machine.machine_id)
                    approval = (self._execution_approval_for_machine(snapshot, unit, machine, original=original_approval,
                                approval_snapshot=approval_snapshot, execution_configs=configs)
                                if approval_error is None else None)
                    candidate_unit = self._memory_calibrated_unit(
                        snapshot, unit, machine, policy,
                        runtime_version=approval.runtime_version if approval else machine.runtime_version,
                        history_cache=memory_history,
                    )
                    decision = evaluate_placement(
                        machine=machine,
                        policy=policy,
                        execution_config=configs.get(machine.machine_id),
                        operational_status=statuses.get(machine.machine_id),
                        grant=grant,
                        profile=profile,
                        job=snapshot,
                        unit=candidate_unit,
                        approvals=approvals,
                        solver_approval=approval,
                        active_units=active_by_machine.get(machine.machine_id, []),
                        active_profile_units=active_by_machine_profile.get(
                            (machine.machine_id, snapshot.execution_profile_id), []
                        ),
                        pressure_settings=pressure_settings,
                    )
                    required_machine_id = unit.required_machine_id or snapshot.placement.required_machine_id
                    if required_machine_id and machine.machine_id != required_machine_id:
                        decision.blockers.append(PlacementBlocker(
                            code="required_machine",
                            category="authorization",
                            message=f"Unit 被限定到机器 {required_machine_id}",
                            required=required_machine_id,
                            available=machine.machine_id,
                        ))
                        decision.eligible = False
                    if approval_error is not None:
                        decision.blockers.append(PlacementBlocker(
                            code=approval_error.reason_code,
                            category="solver",
                            message=approval_error.message,
                        ))
                        decision.eligible = False
                    if (
                        grant is not None
                        and project_concurrency_used >= grant.max_running_units
                    ):
                        decision.blockers.append(PlacementBlocker(
                            code="project_concurrency",
                            category="fairness",
                            message="项目的并发 Unit 上限已占满",
                            required=project_concurrency_used + 1,
                            available=grant.max_running_units,
                            unit="slot",
                            details={
                                "project_id": snapshot.project_id,
                                "active_units": project_concurrency["active_units"],
                                "prepared_units": project_concurrency["prepared_units"],
                            },
                        ))
                        decision.eligible = False
                    if decision.eligible and self._solver_for_assignment(
                        snapshot, unit, machine, policy,
                        execution_approval=approval,
                    ) is None:
                        decision.blockers.append(PlacementBlocker(
                            code="solver_unavailable",
                            category="solver",
                            message="机器没有满足合同的已批准 solver",
                        ))
                        decision.eligible = False
                    evaluations.append(decision)

            unique_blockers: dict[tuple[str, str], dict] = {}
            for evaluation in evaluations:
                for blocker in evaluation.blockers:
                    unique_blockers[(blocker.code, blocker.message)] = blocker.model_dump(mode="json")
            if unit.status == WorkUnitStatus.QUEUED and not dispatch_ready:
                blocker = PlacementBlocker(
                    code="dispatch_backoff",
                    category="bundle",
                    message="启动前传输失败，Dispatcher 正在退避后自动重试",
                    available=(unit.dispatch_not_before_at.isoformat() if unit.dispatch_not_before_at else None),
                )
                unique_blockers[(blocker.code, blocker.message)] = blocker.model_dump(mode="json")
            units_payload.append({
                "work_unit_id": unit.work_unit_id,
                "ordinal": unit.ordinal,
                "status": unit.status.value,
                "priority": snapshot.priority,
                "effective_priority": snapshot.effective_priority,
                "priority_ceiling": snapshot.priority_ceiling_snapshot,
                "priority_wait_seconds": max(
                    0.0, (generated_at - snapshot.created_at).total_seconds()
                ),
                "retryable": (
                    unit.status == WorkUnitStatus.FAILED_RETRIABLE
                    and unit.attempt_count < unit.max_attempts
                ),
                "failure_reason": unit.failure_reason,
                "queue_position": queue_positions.get((snapshot.job_id, unit.work_unit_id)),
                "dispatch_phase": (
                    "backoff"
                    if unit.status == WorkUnitStatus.QUEUED and not dispatch_ready
                    else
                    "prepared"
                    if reservations.get((snapshot.job_id, unit.work_unit_id)) is not None
                    and reservations[(snapshot.job_id, unit.work_unit_id)].state == "prepared"
                    else "preparing"
                    if reservations.get((snapshot.job_id, unit.work_unit_id)) is not None
                    else "queued"
                    if unit.status == WorkUnitStatus.QUEUED
                    else "collecting"
                    if unit.status == WorkUnitStatus.COLLECTING
                    else "solving"
                    if unit.status == WorkUnitStatus.RUNNING
                    else unit.status.value
                ),
                "dispatch_failure_count": unit.dispatch_failure_count,
                "dispatch_not_before_at": (
                    unit.dispatch_not_before_at.isoformat()
                    if unit.dispatch_not_before_at is not None else None
                ),
                "resolved_resources": (
                    unit.resolved_resources.model_dump(mode="json")
                    if unit.resolved_resources is not None
                    else {
                        "source": "origin_legacy",
                        "policy_revision": 1,
                        "resources": unit.resources.model_dump(mode="json"),
                    }
                ),
                "eligible_machine_count": sum(item.eligible for item in evaluations),
                "machines": [item.model_dump(mode="json") for item in evaluations],
                "blockers": list(unique_blockers.values()),
            })
        return {
            "job_id": snapshot.job_id,
            "generated_at": generated_at.isoformat(),
            "project_concurrency": project_concurrency,
            "units": units_payload,
        }

    def prepare_dispatch_once(
        self,
        *,
        actor_id: str,
        ready_for_assignment: Callable[[JobEnvelope, WorkUnit], bool] | None = None,
        should_continue: Callable[[], bool] | None = None,
        ttl_s: int = 600,
        excluded_machine_ids: set[str] | None = None,
    ) -> DispatchReservation | None:
        """Persist one fair standby selection without creating an Attempt."""

        from .dispatch_policy import policy_for
        scheduling = policy_for(self.repository)
        performance_history: dict = {}
        hydration = _DispatchHydrationCache(self.repository)
        now = datetime.now(timezone.utc)
        all_jobs = self.repository.list_operational_jobs(
            statuses={JobStatus.QUEUED, JobStatus.RUNNING},
        )
        jobs = [job for job in all_jobs if job.status in {JobStatus.QUEUED, JobStatus.RUNNING}]
        self._sort_dispatch_jobs(jobs, now, policy=scheduling)
        active_reservations = self.repository.list_dispatch_reservations(active_only=True)
        reserved_units = {
            (reservation.job_id, reservation.work_unit_id) for reservation in active_reservations
        }
        reservations_by_machine: dict[str, list[DispatchReservation]] = {}
        for reservation in active_reservations:
            reservations_by_machine.setdefault(reservation.machine_id, []).append(reservation)

        machines = [m for m in self.repository.list_machines()
                    if m.machine_id not in (excluded_machine_ids or set())]
        configs = {
            item.machine_id: item for item in self.repository.list_machine_execution_configs()
        }
        policies = {machine.machine_id: self.repository.get_policy(machine.machine_id)
                    for machine in machines}
        approval_snapshot = _DispatchApprovalSnapshot(self.repository)
        statuses = {
            item.machine_id: item for item in self.repository.list_machine_operational_statuses()
        }
        active_by_machine: dict[str, list[WorkUnit]] = {}
        active_by_machine_profile: dict[tuple[str, str], list[WorkUnit]] = {}
        quarantined_machine_ids: set[str] = set()
        project_by_job: dict[str, str] = {}
        active_units_by_project: dict[str, int] = {}
        for active_job in all_jobs:
            project_by_job[active_job.job_id] = active_job.project_id
            for active_unit in active_job.work_units:
                if (
                    active_unit.assigned_machine_id
                    and active_unit.status == WorkUnitStatus.RECONCILE_PENDING
                ):
                    quarantined_machine_ids.add(active_unit.assigned_machine_id)
                if active_unit.assigned_machine_id and active_unit.status in {
                    WorkUnitStatus.ASSIGNED,
                    WorkUnitStatus.RUNNING,
                    WorkUnitStatus.RECONCILE_PENDING,
                }:
                    active_units_by_project[active_job.project_id] = (
                        active_units_by_project.get(active_job.project_id, 0) + 1
                    )
                    active_by_machine.setdefault(active_unit.assigned_machine_id, []).append(active_unit)
                    active_by_machine_profile.setdefault(
                        (active_unit.assigned_machine_id, active_job.execution_profile_id), []
                    ).append(active_unit)
        prepared_units_by_project: dict[str, int] = {}
        for reservation in active_reservations:
            project_id = project_by_job.get(reservation.job_id)
            if (
                project_id is not None
                and reservation.state in {"preparing", "prepared", "activating"}
            ):
                prepared_units_by_project[project_id] = (
                    prepared_units_by_project.get(project_id, 0) + 1
                )

        approvals = self.repository.list_approvals()
        pressure_settings = self.repository.get_feature_settings().pressure_policy
        memory_history: dict[tuple[str, str], list[JobEnvelope]] = {}
        for job_record in jobs:
            if should_continue is not None and not should_continue():
                return None
            job = job_record
            grant = self._effective_person_grant(job)
            from .personal_runtime import policy_store
            try:
                policy_store(self).check_running_capacity(job.user_id)
            except SubmissionPolicyError:
                continue
            profile = self.repository.get_profile(job.execution_profile_id)
            if grant is None or profile is None:
                continue
            project_running = active_units_by_project.get(job.project_id, 0)
            project_prepared = prepared_units_by_project.get(job.project_id, 0)
            # Prewarm allowance: a project at its full running cap still keeps
            # exactly one prepared standby so the next unit starts the moment
            # a slot frees instead of waiting for a full re-scheduling pass.
            # Prepared reservations hold no Attempt and never count toward the
            # cap here; activation goes through activate_dispatch_reservation,
            # which re-checks the grant cap before creating the Attempt, so
            # the overhang can never turn into an over-cap run.
            prewarm_allowance = 1 if project_running >= grant.max_running_units else 0
            if project_running + project_prepared >= grant.max_running_units + prewarm_allowance:
                continue
            for unit in job.work_units:
                if should_continue is not None and not should_continue():
                    return None
                if unit.status != WorkUnitStatus.QUEUED:
                    continue
                if not self._dispatch_ready(unit, now):
                    continue
                if (job.job_id, unit.work_unit_id) in reserved_units:
                    continue
                candidates = sorted(
                    [
                        machine for machine in machines
                        if machine.machine_id not in quarantined_machine_ids
                    ],
                    key=lambda machine: (
                        machine.machine_id
                        != (unit.preferred_machine_id or job.placement.preferred_machine_id),
                        *self._machine_selection_key(
                            machine,
                            unit, job=job, history_cache=performance_history, scheduling=scheduling,
                            active_count=len(active_by_machine.get(machine.machine_id, [])),
                            prepared_count=len(reservations_by_machine.get(machine.machine_id, [])),
                            policies=policies, execution_configs=configs, runtime_statuses=statuses,
                            approval_snapshot=approval_snapshot,
                        ),
                    ),
                )
                required_machine_id = unit.required_machine_id or job.placement.required_machine_id
                if required_machine_id:
                    candidates = [
                        machine for machine in candidates if machine.machine_id == required_machine_id
                    ]
                previous_machine_ids = {
                    attempt.machine_id for attempt in unit.attempts if attempt.machine_id
                }
                if previous_machine_ids and not job.retry_policy.allow_migration:
                    latest_machine = unit.attempts[-1].machine_id
                    candidates = [
                        machine for machine in candidates if machine.machine_id == latest_machine
                    ]
                for machine in candidates:
                    policy = policies.get(machine.machine_id)
                    try:
                        approval = self._execution_approval_for_machine(
                            job, unit, machine, approval_snapshot=approval_snapshot, execution_configs=configs,
                        )
                    except ExecutionCompatibilityError:
                        continue
                    candidate_unit = self._memory_calibrated_unit(
                        job, unit, machine, policy,
                        runtime_version=approval.runtime_version if approval else machine.runtime_version,
                        history_cache=memory_history,
                        execution_approval=approval,
                    )
                    decision = evaluate_placement(
                        machine=machine,
                        policy=policy,
                        execution_config=configs.get(machine.machine_id),
                        operational_status=statuses.get(machine.machine_id),
                        grant=grant,
                        profile=profile,
                        job=job,
                        unit=candidate_unit,
                        approvals=approvals,
                        solver_approval=approval,
                        active_units=active_by_machine.get(machine.machine_id, []),
                        active_profile_units=active_by_machine_profile.get(
                            (machine.machine_id, job.execution_profile_id), []
                        ),
                        prepared_slots=len(reservations_by_machine.get(machine.machine_id, [])),
                        standby=True,
                        pressure_settings=pressure_settings,
                        now=now,
                    )
                    if not decision.eligible or policy is None:
                        continue
                    solver_variant = self._solver_for_assignment(job, unit, machine, policy, execution_approval=approval)
                    if solver_variant is None:
                        continue
                    if ready_for_assignment is not None:
                        if should_continue is not None and not should_continue():
                            return None
                        hydrated, hydrated_unit = hydration.get(job.job_id, unit.work_unit_id)
                        if (
                            hydrated is None
                            or hydrated_unit is None
                            or hydrated_unit.status != WorkUnitStatus.QUEUED
                            or not ready_for_assignment(hydrated, hydrated_unit)
                        ):
                            break
                    if should_continue is not None and not should_continue():
                        return None
                    used_slots = {
                        reservation.slot_index
                        for reservation in reservations_by_machine.get(machine.machine_id, [])
                    }
                    slot_index = next(
                        (
                            index for index in range(max(0, decision.occupied_slots))
                            if index not in used_slots
                        ),
                        None,
                    )
                    if slot_index is None:
                        continue
                    resolved = self._assignment_resources(
                        candidate_unit,
                        machine,
                        policy,
                        # Standby activation requires at least one current
                        # slot to leave execution first.
                        active_count=max(0, decision.occupied_slots - 1),
                        standby=True,
                    )
                    reservation = DispatchReservation(
                        active_key=f"{machine.machine_id}:{slot_index}",
                        job_id=job.job_id,
                        job_request_hash=job.request_hash,
                        work_unit_id=unit.work_unit_id,
                        machine_id=machine.machine_id,
                        slot_index=slot_index,
                        solver_variant=solver_variant,
                        solver_approval_id=approval.approval_id if approval else None,
                        solver_compatibility_fingerprint=(approval.fingerprint if approval else None),
                        runtime_version=approval.runtime_version if approval else None,
                        resolved_resources=resolved,
                        expires_at=now + timedelta(seconds=ttl_s),
                    )
                    reservation.external_run_id = (
                        f"ssh-{machine.machine_id}-{reservation.reservation_id}"
                    )
                    from .repository import RevisionConflictError
                    try:
                        if not self.repository.put_dispatch_reservation(
                            reservation, expected_job_revision=job.revision,
                        ):
                            continue
                    except RevisionConflictError:
                        # Do not seal a stale solver/resource selection. The
                        # next normal cycle will read the current Job envelope.
                        continue
                    self._event(
                        "dispatch_reservation.created",
                        actor_id,
                        "dispatch_reservation",
                        reservation.reservation_id,
                        job_id=job.job_id,
                        work_unit_id=unit.work_unit_id,
                        machine_id=machine.machine_id,
                        slot_index=slot_index,
                    )
                    return reservation
        return None

    def bind_dispatch_reservation_request(
        self,
        reservation_id: str,
        *,
        job_request_hash: str,
        request: dict[str, Any],
        actor_id: str,
    ) -> DispatchReservation:
        """Persist the exact built request identity before any publication."""
        reservation = self.repository.get_dispatch_reservation(reservation_id)
        if reservation is None or reservation.state != "preparing" or reservation.active_key is None:
            raise ValueError("standby reservation changed before request publication")
        job = self.repository.get_job(reservation.job_id, hydrate_blobs=False)
        if (job is None or job.request_hash != job_request_hash
                or reservation.job_request_hash not in {None, job_request_hash}):
            raise ValueError("Job request changed before standby publication")
        expected = {
            "external_run_id": reservation.external_run_id,
            "machine_id": reservation.machine_id,
            "job_id": reservation.job_id,
            "work_unit_id": reservation.work_unit_id,
            "dispatch_reservation_id": reservation.reservation_id,
            "dispatch_state": "prepared",
            "project_id": job.project_id,
            "profile_id": job.execution_profile_id,
        }
        if any(request.get(key) != value for key, value in expected.items()):
            raise ValueError("standby built request identity mismatch")
        if reservation.runtime_version is not None and request.get("runtime_version") != reservation.runtime_version:
            raise ValueError("standby built request runtime mismatch")
        request_hash = request.get("request_hash")
        if (not isinstance(request_hash, str) or len(request_hash) != 64
                or any(character not in "0123456789abcdef" for character in request_hash)):
            raise ValueError("standby built request hash is invalid")
        if reservation.request_hash not in {None, request_hash}:
            raise ValueError("standby immutable request hash changed")
        reservation.job_request_hash = job_request_hash
        reservation.request_hash = request_hash
        if not self.repository.put_dispatch_reservation(reservation, expected_state="preparing"):
            raise ValueError("standby reservation changed before request publication")
        self._event("dispatch_reservation.request_bound", actor_id, "dispatch_reservation",
                    reservation_id, job_id=reservation.job_id, work_unit_id=reservation.work_unit_id,
                    request_hash=request_hash, job_request_hash=job_request_hash)
        return reservation

    def mark_dispatch_reservation_prepared(
        self,
        reservation_id: str,
        *,
        actor_id: str,
        prepared_ttl_s: int = 86_400,
    ) -> DispatchReservation:
        reservation = self.repository.get_dispatch_reservation(reservation_id)
        if reservation is None:
            raise KeyError(f"dispatch reservation not found: {reservation_id}")
        if reservation.state == "preparing":
            reservation.state = "prepared"
            reservation.prepared_at = datetime.now(timezone.utc)
            # Preparation has already paid the bundle-transfer cost. Keep the
            # standby long enough for scientific Units that routinely run for
            # hours; activation still revalidates machine, approval, runtime,
            # solver, quota, pressure, and queued state before creating an
            # Attempt. The short creation TTL remains the preparation timeout.
            reservation.expires_at = max(
                reservation.expires_at,
                reservation.prepared_at
                + timedelta(seconds=max(600, min(prepared_ttl_s, 7 * 86_400))),
            )
            if not self.repository.put_dispatch_reservation(reservation, expected_state="preparing"):
                raise RuntimeError("dispatch reservation slot changed while preparing")
            self._event(
                "dispatch_reservation.prepared",
                actor_id,
                "dispatch_reservation",
                reservation.reservation_id,
                job_id=reservation.job_id,
                work_unit_id=reservation.work_unit_id,
                machine_id=reservation.machine_id,
            )
        return reservation

    def finish_dispatch_reservation(
        self,
        reservation_id: str,
        *,
        state: str,
        reason: str,
        actor_id: str,
        expected_state: str | None = None,
    ) -> DispatchReservation:
        if state not in {"consumed", "cancelled", "expired"}:
            raise ValueError("invalid terminal dispatch reservation state")
        reservation = self.repository.get_dispatch_reservation(reservation_id)
        if reservation is None:
            raise KeyError(f"dispatch reservation not found: {reservation_id}")
        if reservation.state in {"consumed", "cancelled", "expired"}:
            return reservation
        if expected_state is not None and reservation.state != expected_state:
            return reservation
        previous_state = reservation.state
        reservation.state = state
        reservation.reason = reason
        reservation.active_key = None
        if state == "consumed":
            reservation.activated_at = reservation.activated_at or datetime.now(timezone.utc)
        if not self.repository.put_dispatch_reservation(reservation, expected_state=previous_state):
            return self.repository.get_dispatch_reservation(reservation_id)
        self._event(
            f"dispatch_reservation.{state}",
            actor_id,
            "dispatch_reservation",
            reservation.reservation_id,
            job_id=reservation.job_id,
            work_unit_id=reservation.work_unit_id,
            machine_id=reservation.machine_id,
            reason=reason,
        )
        return reservation

    def activate_dispatch_reservation(
        self,
        reservation_id: str,
        *,
        actor_id: str,
        ready_for_assignment: Callable[[JobEnvelope, WorkUnit], bool] | None = None,
    ) -> Assignment | None:
        """Create the first Attempt only when a prepared slot can actually run."""

        reservation = self.repository.get_dispatch_reservation(reservation_id)
        if reservation is None or reservation.state != "prepared":
            return None
        if reservation.expires_at <= datetime.now(timezone.utc):
            return None  # Cancellation/reconciliation owns this original identity.

        def activation_evidence(current: DispatchReservation) -> bool:
            current_job = self.repository.get_job(current.job_id, hydrate_blobs=False)
            if current.activated_at is not None:
                return True
            if current_job is not None and any(
                attempt.dispatch_reservation_id == current.reservation_id
                or (current.external_run_id is not None
                    and attempt.external_run_id == current.external_run_id)
                for current_unit in current_job.work_units for attempt in current_unit.attempts
            ):
                # Even a submitting Attempt owns potentially delivered activation.
                return True
            remote = (self.repository.get_remote_run(current.external_run_id)
                      if current.external_run_id is not None else None)
            return bool(remote is not None and (
                remote.state not in {RemoteRunState.STAGED, RemoteRunState.PREPARED,
                                     RemoteRunState.QUEUED, RemoteRunState.CANCELLED}
                or remote.artifacts_available
            ))

        if activation_evidence(reservation):
            return None

        def request_retirement(reason: str, *, event_type: str = "dispatch_reservation.invalidated") -> None:
            current = self.repository.get_dispatch_reservation(reservation_id)
            if (current is None or current.active_key is None or current.state != "prepared"
                    or current.request_hash != reservation.request_hash
                    or current.external_run_id != reservation.external_run_id
                    or activation_evidence(current)):
                return
            current.expires_at = datetime.now(timezone.utc)
            current.reason = reason
            if self.repository.put_dispatch_reservation(current, expected_state="prepared"):
                self._event(event_type, actor_id, "dispatch_reservation", reservation_id,
                            job_id=current.job_id, work_unit_id=current.work_unit_id, reason=reason)

        job = self.repository.get_job(reservation.job_id)
        if job is None:
            request_retirement("job no longer exists")
            return None
        unit = next(
            (item for item in job.work_units if item.work_unit_id == reservation.work_unit_id), None
        )
        if unit is None or unit.status != WorkUnitStatus.QUEUED:
            request_retirement("unit is no longer queued")
            return None
        if reservation.job_request_hash is not None and reservation.job_request_hash != job.request_hash:
            request_retirement("Job request changed after preparation")
            return None
        try:
            original_approval = self._resolve_unit_approval(job, unit)
        except ExecutionCompatibilityError:
            request_retirement("solver approval became invalid after preparation")
            return None
        approval = original_approval
        if reservation.solver_approval_id is not None:
            from .runtime_compatibility import is_registered_runtime_successor
            approval = self.repository.get_solver_approval(reservation.solver_approval_id)
            if (approval is None or not approval.is_active() or original_approval is None
                    or (approval.approval_id != original_approval.approval_id
                        and not is_registered_runtime_successor(original_approval, approval))
                    or approval.fingerprint != reservation.solver_compatibility_fingerprint
                    or approval.runtime_version != reservation.runtime_version):
                request_retirement("runtime or approval changed after preparation")
                return None
        elif original_approval is not None:
            request_retirement("runtime or approval changed after preparation")
            return None
        machine = self.repository.get_machine(reservation.machine_id)
        policy = self.repository.get_policy(reservation.machine_id)
        grant = self._effective_person_grant(job)
        profile = self.repository.get_profile(job.execution_profile_id)
        if machine is None or policy is None:
            request_retirement("prepared machine or owner policy no longer exists")
            return None
        if grant is None or profile is None:
            return None
        if (policy.full_cpu_override is not None
                and policy.full_cpu_override.max_threads_per_attempt is not None
                and reservation.resolved_resources.resources.cpus > min(
                    policy.effective_cpu_cap(machine.total_cpus),
                    policy.full_cpu_override.max_threads_per_attempt)):
            # Retire the original unstarted bundle through acknowledged remote
            # cancellation, then let normal scheduling use the new CPU cap.
            request_retirement("CPU thread limit changed after preparation")
            return None
        all_jobs = self.repository.list_operational_jobs(
            statuses={JobStatus.QUEUED, JobStatus.RUNNING},
        )
        if any(
            active_unit.assigned_machine_id == machine.machine_id
            and active_unit.status == WorkUnitStatus.RECONCILE_PENDING
            for active_job in all_jobs
            for active_unit in active_job.work_units
        ):
            return None
        active_units = [
            active_unit
            for active_job in all_jobs
            for active_unit in active_job.work_units
            if active_unit.assigned_machine_id == machine.machine_id
            and active_unit.status in {
                WorkUnitStatus.ASSIGNED,
                WorkUnitStatus.RUNNING,
                WorkUnitStatus.RECONCILE_PENDING,
            }
        ]
        active_project_units = sum(
            active_unit.status in {
                WorkUnitStatus.ASSIGNED,
                WorkUnitStatus.RUNNING,
                WorkUnitStatus.RECONCILE_PENDING,
            }
            for active_job in all_jobs
            if active_job.project_id == job.project_id
            for active_unit in active_job.work_units
        )
        if active_project_units >= grant.max_running_units:
            return None
        active_profile_units = [
            active_unit
            for active_job in all_jobs
            if active_job.execution_profile_id == job.execution_profile_id
            for active_unit in active_job.work_units
            if active_unit.assigned_machine_id == machine.machine_id
            and active_unit.status in {
                WorkUnitStatus.ASSIGNED,
                WorkUnitStatus.RUNNING,
                WorkUnitStatus.RECONCILE_PENDING,
            }
        ]
        status = self.repository.get_machine_operational_status(machine.machine_id)
        activation_unit = unit.model_copy(deep=True) if policy.shared_machine else unit
        if policy.shared_machine:
            # Recheck the actual sealed bundle, not its smaller original floor.
            activation_unit.resources = reservation.resolved_resources.resources.model_copy(deep=True)
            activation_unit.resolved_resources = reservation.resolved_resources.model_copy(deep=True)
        decision = evaluate_placement(
            machine=machine,
            policy=policy,
            execution_config=self.repository.get_machine_execution_config(machine.machine_id),
            operational_status=status,
            grant=grant,
            profile=profile,
            job=job,
            unit=activation_unit,
            approvals=self.repository.list_approvals(),
            solver_approval=approval,
            active_units=active_units,
            active_profile_units=active_profile_units,
            pressure_settings=self.repository.get_feature_settings().pressure_policy,
        )
        if not decision.eligible:
            unavailable = [blocker.code for blocker in decision.blockers
                           if blocker.category not in {"capacity", "resources"}]
            if unavailable:
                request_retirement("prepared machine cannot accept work: " + ", ".join(unavailable))
            else:
                config = self.repository.get_machine_execution_config(machine.machine_id)
                # Give a newly prepared bundle one existing worker polling interval
                # before retiring it merely because its original slot is still busy.
                grace_s = config.poll_interval_s if config is not None else 15
                prepared_at = reservation.prepared_at or reservation.created_at
                if (datetime.now(timezone.utc) - prepared_at).total_seconds() >= grace_s:
                    alternative = self._prepared_backfill_machine(
                        reservation, job, unit, grant, profile, all_jobs,
                        ready_for_assignment=ready_for_assignment,
                    )
                    if alternative is not None:
                        request_retirement(
                            f"prepared slot blocked; eligible backfill machine {alternative}",
                            event_type="dispatch_reservation.backfill_requested",
                        )
            return None
        solver = self._solver_for_assignment(job, unit, machine, policy, execution_approval=approval)
        if solver != reservation.solver_variant:
            request_retirement("solver eligibility changed after preparation")
            return None
        if self._higher_priority_waiter_for_machine(
            reservation=reservation,
            reserved_job=job,
            machine=machine,
            policy=policy,
            all_jobs=all_jobs,
            active_units=active_units,
            approvals=self.repository.list_approvals(),
            actor_id=actor_id,
            ready_for_assignment=ready_for_assignment,
        ):
            return None
        from .repository import RevisionConflictError
        state: dict[str, str] = {}

        def persist_activation(current: JobEnvelope) -> None:
            if current.revision != job.revision:
                raise RevisionConflictError("Job envelope changed during standby activation")
            current_reservation = self.repository.get_dispatch_reservation(reservation_id)
            if (current_reservation is None or current_reservation.state != "prepared"
                    or current_reservation.active_key != reservation.active_key
                    or current_reservation.request_hash != reservation.request_hash):
                raise RevisionConflictError("standby reservation changed during activation")
            if reservation.solver_approval_id is not None:
                current_approval = self.repository.get_solver_approval(reservation.solver_approval_id)
                if (current_approval is None or not current_approval.is_active()
                        or current_approval.fingerprint != reservation.solver_compatibility_fingerprint
                        or current_approval.runtime_version != reservation.runtime_version):
                    raise RevisionConflictError("solver approval changed during standby activation")
            current_unit = next(
                item for item in current.work_units if item.work_unit_id == reservation.work_unit_id
            )
            if current_unit.status != WorkUnitStatus.QUEUED:
                raise _AssignmentStateChanged
            current_unit.status = WorkUnitStatus.ASSIGNED
            current_unit.assigned_machine_id = reservation.machine_id
            current_unit.attempt_count += 1
            attempt_id = self._fresh_attempt_id(current_unit)
            current_unit.attempts.append(WorkUnitAttempt(
                attempt_id=attempt_id,
                machine_id=reservation.machine_id,
                external_run_id=reservation.external_run_id,
                state="submitting",
                assigned_at=datetime.now(timezone.utc),
                activation_requested_at=datetime.now(timezone.utc),
                activation_retry_count=1,
                solver_variant=reservation.solver_variant,
                solver_approval_id=reservation.solver_approval_id,
                solver_compatibility_fingerprint=reservation.solver_compatibility_fingerprint,
                runtime_version=reservation.runtime_version,
                dispatch_reservation_id=reservation.reservation_id,
                resolved_resources=reservation.resolved_resources.model_copy(deep=True),
                pressure_state=(status.pressure_state if status else None),
                effective_capacity=decision.effective_capacity,
                capacity_reason=decision.capacity_reason,
                capacity_decision_at=(status.capacity_decision_at if status else None),
                telemetry_observed_at=(status.last_metric_at if status else None),
            ))
            current.status = JobStatus.RUNNING
            current.last_scheduled_at = datetime.now(timezone.utc)
            state["attempt_id"] = attempt_id

        def reserve_activation(current: JobEnvelope) -> None:
            from .personal_runtime import reserve_attempt
            current_unit = next(item for item in current.work_units if item.work_unit_id == unit.work_unit_id)
            reserve_attempt(self, current, current_unit, current_unit.attempts[-1])

        try:
            self.repository.mutate_job(
                job.job_id,
                persist_activation,
                before_write=reserve_activation,
                retries=1,
                hydrate_blobs=False,
            )
        except RevisionConflictError:
            # A competing activation may already own this reservation. Leave
            # its Attempt and remote lifecycle to the existing reconciliation.
            latest = self.repository.get_job(job.job_id, hydrate_blobs=False)
            if latest is not None and any(
                attempt.dispatch_reservation_id == reservation_id
                and attempt.state not in {"completed", "failed", "cancelled"}
                for current_unit in latest.work_units for attempt in current_unit.attempts
            ):
                return None
            # Keep the external identity and slot until normal reconciliation
            # acknowledges remote cancellation. A metadata conflict must not
            # turn uncertain prepared delivery into another free reservation.
            request_retirement("Job envelope changed during standby activation",
                               event_type="dispatch_reservation.activation_conflict")
            return None
        except (_AssignmentStateChanged, SharedCapacityConflict, SubmissionPolicyError, CreditError):
            return None
        reservation.state = "activating"
        reservation.activated_at = datetime.now(timezone.utc)
        self.repository.put_dispatch_reservation(reservation, expected_state="prepared")
        return Assignment(
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
            machine_id=machine.machine_id,
            scheduler="pilot-standby",
            attempt_id=state["attempt_id"],
            solver_variant=reservation.solver_variant,
            solver_approval_id=reservation.solver_approval_id,
            solver_compatibility_fingerprint=reservation.solver_compatibility_fingerprint,
            runtime_version=reservation.runtime_version,
            dispatch_reservation_id=reservation.reservation_id,
            prepared=True,
            external_run_id=reservation.external_run_id,
        )

    def _prepared_backfill_machine(
        self, reservation: DispatchReservation, job: JobEnvelope, unit: WorkUnit,
        grant: ProjectGrant, profile: ExecutionProfile, all_jobs: list[JobEnvelope],
        *, ready_for_assignment: Callable[[JobEnvelope, WorkUnit], bool] | None,
    ) -> str | None:
        """Prove another normal slot fits; cancellation and scheduling own the move."""
        now = datetime.now(timezone.utc)
        if not self._dispatch_ready(unit, now):
            return None
        if ready_for_assignment is not None and not ready_for_assignment(job, unit):
            return None
        required = unit.required_machine_id or job.placement.required_machine_id
        retry_pinned = bool(any(attempt.machine_id for attempt in unit.attempts)
                            and not job.retry_policy.allow_migration)
        previous_machine = unit.attempts[-1].machine_id if retry_pinned else None
        approvals = self.repository.list_approvals()
        pressure_settings = self.repository.get_feature_settings().pressure_policy
        memory_history: dict[tuple[str, str], list[JobEnvelope]] = {}
        for machine in self.repository.list_machines():
            if (machine.machine_id == reservation.machine_id
                    or (required and machine.machine_id != required)
                    or (retry_pinned and machine.machine_id != previous_machine)):
                continue
            active = [item for active_job in all_jobs for item in active_job.work_units
                      if item.assigned_machine_id == machine.machine_id and item.status in {
                          WorkUnitStatus.ASSIGNED, WorkUnitStatus.RUNNING,
                          WorkUnitStatus.RECONCILE_PENDING,
                      }]
            if any(item.status == WorkUnitStatus.RECONCILE_PENDING for item in active):
                continue
            status = self.repository.get_machine_operational_status(machine.machine_id)
            if status is None or not fresh(status.last_metric_at, now):
                continue
            active_profile = [item for active_job in all_jobs
                              if active_job.execution_profile_id == job.execution_profile_id
                              for item in active_job.work_units if item in active]
            try:
                approval = self._execution_approval_for_machine(job, unit, machine)
            except ExecutionCompatibilityError:
                continue
            policy = self.repository.get_policy(machine.machine_id)
            calibrated = self._memory_calibrated_unit(
                job, unit, machine, policy,
                runtime_version=approval.runtime_version if approval else machine.runtime_version,
                history_cache=memory_history,
            )
            # Backfill cannot be justified by shrinking the sealed resource envelope.
            candidate = unit.model_copy(deep=True)
            candidate.resolved_resources = reservation.resolved_resources.model_copy(deep=True)
            candidate.resources = reservation.resolved_resources.resources.model_copy(deep=True)
            candidate.resources = candidate.resources.model_copy(update={
                name: max(getattr(candidate.resources, name), getattr(unit.resources, name),
                          getattr(calibrated.resources, name))
                for name in ("cpus", "memory_mb", "disk_mb", "gpus")
            })
            decision = evaluate_placement(
                machine=machine, policy=policy,
                execution_config=self.repository.get_machine_execution_config(machine.machine_id),
                operational_status=status,
                grant=grant, profile=profile, job=job, unit=candidate,
                approvals=approvals, solver_approval=approval, active_units=active,
                active_profile_units=active_profile, pressure_settings=pressure_settings, now=now,
            )
            if decision.eligible and self._solver_for_assignment(
                job, candidate, machine, policy, execution_approval=approval,
            ) is not None:
                return machine.machine_id
        return None

    def _higher_priority_waiter_for_machine(
        self,
        *,
        reservation: DispatchReservation,
        reserved_job: JobEnvelope,
        machine: MachineState,
        policy: MachinePolicy,
        all_jobs: list[JobEnvelope],
        active_units: list[WorkUnit],
        approvals: list[ApprovalRecord],
        actor_id: str,
        ready_for_assignment: Callable[[JobEnvelope, WorkUnit], bool] | None,
    ) -> bool:
        """Defer standby activation when a strictly higher rank can use its slot.

        A prepared bundle is a latency optimization, not a priority claim. It
        remains sealed and reusable while the higher-priority Unit runs, so no
        scientific work is cancelled and no Attempt is consumed.
        """

        now = datetime.now(timezone.utc)
        from .dispatch_policy import policy_for
        scheduling = policy_for(self.repository)
        # Prepared bytes are a latency optimization, not an independent lane.
        # Rank every candidate and the reserved Job with the same policy. The
        # normal Job waiting guard protects large work within its priority band;
        # an old reservation must not jump the operator's higher-priority queue.
        ordered = [candidate for candidate in all_jobs
                   if candidate.status in {JobStatus.QUEUED, JobStatus.RUNNING}
                   and candidate.job_id != reserved_job.job_id]
        ordered.append(reserved_job)
        self._sort_dispatch_jobs(ordered, now, policy=scheduling)
        reserved_index = next(index for index, item in enumerate(ordered)
                              if item.job_id == reserved_job.job_id)
        higher_ranked = ordered[:reserved_index]
        reservations_by_unit = {
            (item.job_id, item.work_unit_id): item
            for item in self.repository.list_dispatch_reservations(active_only=True)
            if item.reservation_id != reservation.reservation_id
        }
        active_by_project: dict[str, int] = {}
        active_by_profile: dict[str, list[WorkUnit]] = {}
        for active_job in all_jobs:
            for active_unit in active_job.work_units:
                if active_unit.status not in {
                    WorkUnitStatus.ASSIGNED,
                    WorkUnitStatus.RUNNING,
                    WorkUnitStatus.RECONCILE_PENDING,
                }:
                    continue
                active_by_project[active_job.project_id] = (
                    active_by_project.get(active_job.project_id, 0) + 1
                )
                if active_unit.assigned_machine_id == machine.machine_id:
                    active_by_profile.setdefault(active_job.execution_profile_id, []).append(
                        active_unit
                    )

        candidates = higher_ranked
        status = self.repository.get_machine_operational_status(machine.machine_id)
        execution_config = self.repository.get_machine_execution_config(machine.machine_id)
        pressure_settings = self.repository.get_feature_settings().pressure_policy
        for candidate in candidates:
            grant = self._effective_person_grant(candidate)
            profile = self.repository.get_profile(candidate.execution_profile_id)
            if grant is None or profile is None:
                continue
            if active_by_project.get(candidate.project_id, 0) >= grant.max_running_units:
                continue
            for candidate_unit in candidate.work_units:
                if candidate_unit.status != WorkUnitStatus.QUEUED:
                    continue
                if not self._dispatch_ready(candidate_unit, now):
                    continue
                try:
                    approval = self._execution_approval_for_machine(candidate, candidate_unit, machine)
                except ExecutionCompatibilityError:
                    continue
                other_reservation = reservations_by_unit.get(
                    (candidate.job_id, candidate_unit.work_unit_id)
                )
                if (
                    other_reservation is not None
                    and other_reservation.machine_id != machine.machine_id
                ):
                    continue
                required_machine_id = (
                    candidate_unit.required_machine_id
                    or candidate.placement.required_machine_id
                )
                if required_machine_id and required_machine_id != machine.machine_id:
                    continue
                previous_machine_ids = {
                    attempt.machine_id
                    for attempt in candidate_unit.attempts
                    if attempt.machine_id
                }
                if previous_machine_ids and not candidate.retry_policy.allow_migration:
                    if candidate_unit.attempts[-1].machine_id != machine.machine_id:
                        continue
                decision = evaluate_placement(
                    machine=machine,
                    policy=policy,
                    execution_config=execution_config,
                    operational_status=status,
                    grant=grant,
                    profile=profile,
                    job=candidate,
                    unit=candidate_unit,
                    approvals=approvals,
                    solver_approval=approval,
                    active_units=active_units,
                    active_profile_units=active_by_profile.get(
                        candidate.execution_profile_id,
                        [],
                    ),
                    pressure_settings=pressure_settings,
                    now=now,
                )
                if not decision.eligible:
                    continue
                if self._solver_for_assignment(candidate, candidate_unit, machine, policy) is None:
                    continue
                if ready_for_assignment is not None:
                    hydrated = self.repository.get_job(candidate.job_id)
                    hydrated_unit = (
                        next(
                            (
                                item
                                for item in hydrated.work_units
                                if item.work_unit_id == candidate_unit.work_unit_id
                            ),
                            None,
                        )
                        if hydrated is not None
                        else None
                    )
                    if (
                        hydrated is None
                        or hydrated_unit is None
                        or hydrated_unit.status != WorkUnitStatus.QUEUED
                        or not ready_for_assignment(hydrated, hydrated_unit)
                    ):
                        continue
                return True
        return False

    def schedule_once(
        self,
        *,
        actor_id: str = "scheduler",
        ready_for_assignment: Callable[[JobEnvelope, WorkUnit], bool] | None = None,
        should_continue: Callable[[], bool] | None = None,
        excluded_machine_ids: set[str] | None = None,
    ) -> Assignment | None:
        from .dispatch_policy import policy_for
        scheduling = policy_for(self.repository)
        performance_history: dict = {}
        hydration = _DispatchHydrationCache(self.repository)
        self._auto_retry_failed_units(actor_id=actor_id)
        all_jobs = self.repository.list_operational_jobs(
            statuses={JobStatus.QUEUED, JobStatus.RUNNING}
        )
        jobs = [job for job in all_jobs if job.status in {JobStatus.QUEUED, JobStatus.RUNNING}]
        self._sort_dispatch_jobs(jobs, datetime.now(timezone.utc), policy=scheduling)
        machines = [m for m in self.repository.list_machines()
                    if m.machine_id not in (excluded_machine_ids or set())]
        execution_configs = {
            config.machine_id: config
            for config in self.repository.list_machine_execution_configs()
        }
        policies = {
            machine.machine_id: self.repository.get_policy(machine.machine_id)
            for machine in machines
        }
        approval_snapshot = _DispatchApprovalSnapshot(self.repository)
        runtime_statuses = {
            status.machine_id: status
            for status in self.repository.list_machine_operational_statuses()
        }
        approvals = self.repository.list_approvals()
        pressure_settings = self.repository.get_feature_settings().pressure_policy
        now = datetime.now(timezone.utc)
        reserved_units = {
            (reservation.job_id, reservation.work_unit_id)
            for reservation in self.repository.list_dispatch_reservations(active_only=True)
        }
        memory_history: dict[tuple[str, str], list[JobEnvelope]] = {}
        active_units_by_machine: dict[str, list[WorkUnit]] = {}
        active_units_by_machine_and_profile: dict[tuple[str, str], list[WorkUnit]] = {}
        active_units_by_project: dict[str, int] = {}
        quarantined_machine_ids: set[str] = set()
        for active_job in all_jobs:
            for active_unit in active_job.work_units:
                if (
                    active_unit.assigned_machine_id
                    and active_unit.status == WorkUnitStatus.RECONCILE_PENDING
                ):
                    quarantined_machine_ids.add(active_unit.assigned_machine_id)
                if (
                    active_unit.assigned_machine_id
                    and active_unit.status in {
                        WorkUnitStatus.ASSIGNED,
                        WorkUnitStatus.RUNNING,
                        WorkUnitStatus.RECONCILE_PENDING,
                    }
                ):
                    active_units_by_project[active_job.project_id] = (
                        active_units_by_project.get(active_job.project_id, 0) + 1
                    )
                    active_units_by_machine.setdefault(
                        active_unit.assigned_machine_id,
                        [],
                    ).append(active_unit)
                    active_units_by_machine_and_profile.setdefault(
                        (active_unit.assigned_machine_id, active_job.execution_profile_id),
                        [],
                    ).append(active_unit)

        for job in jobs:
            if should_continue is not None and not should_continue():
                return None
            grant = self._effective_person_grant(job)
            profile = self.repository.get_profile(job.execution_profile_id)
            if grant is None or profile is None:
                continue
            running_for_project = active_units_by_project.get(job.project_id, 0)
            if running_for_project >= grant.max_running_units:
                continue
            for unit in job.work_units:
                if should_continue is not None and not should_continue():
                    return None
                if unit.status != WorkUnitStatus.QUEUED:
                    continue
                if (job.job_id, unit.work_unit_id) in reserved_units:
                    continue
                if not self._dispatch_ready(unit, now):
                    continue
                candidates = [
                    machine for machine in machines
                    if machine.machine_id not in quarantined_machine_ids
                ]
                required_machine_id = unit.required_machine_id or job.placement.required_machine_id
                preferred_machine_id = unit.preferred_machine_id or job.placement.preferred_machine_id
                if required_machine_id:
                    candidates = [
                        machine for machine in candidates
                        if machine.machine_id == required_machine_id
                    ]
                elif preferred_machine_id:
                    candidates = sorted(
                        candidates,
                        key=lambda machine: (
                            machine.machine_id != preferred_machine_id,
                            *self._machine_selection_key(
                                machine,
                                unit, job=job, history_cache=performance_history, scheduling=scheduling,
                                active_count=len(active_units_by_machine.get(machine.machine_id, [])),
                                policies=policies, execution_configs=execution_configs, runtime_statuses=runtime_statuses,
                                approval_snapshot=approval_snapshot,
                            ),
                        ),
                    )
                else:
                    candidates = sorted(
                        candidates,
                        key=lambda machine: self._machine_selection_key(
                            machine,
                            unit, job=job, history_cache=performance_history, scheduling=scheduling,
                            active_count=len(active_units_by_machine.get(machine.machine_id, [])),
                            policies=policies, execution_configs=execution_configs, runtime_statuses=runtime_statuses,
                            approval_snapshot=approval_snapshot,
                        ),
                    )
                previous_machine_ids = {
                    attempt.machine_id for attempt in unit.attempts if attempt.machine_id
                }
                if previous_machine_ids:
                    if job.retry_policy.allow_migration:
                        candidates = sorted(
                            candidates,
                            key=lambda machine: machine.machine_id in previous_machine_ids,
                        )
                    else:
                        latest_machine = unit.attempts[-1].machine_id
                        candidates = [
                            machine for machine in candidates
                            if machine.machine_id == latest_machine
                        ]
                for machine in candidates:
                    execution_config = execution_configs.get(machine.machine_id)
                    policy = policies.get(machine.machine_id)
                    try:
                        approval = self._execution_approval_for_machine(
                            job, unit, machine, approval_snapshot=approval_snapshot, execution_configs=execution_configs,
                        )
                    except ExecutionCompatibilityError:
                        continue
                    candidate_unit = self._memory_calibrated_unit(
                        job, unit, machine, policy,
                        runtime_version=approval.runtime_version if approval else machine.runtime_version,
                        history_cache=memory_history,
                        execution_approval=approval,
                    )
                    runtime_status = runtime_statuses.get(machine.machine_id)
                    active_units = active_units_by_machine.get(machine.machine_id, [])
                    active_profile_units = active_units_by_machine_and_profile.get(
                        (machine.machine_id, job.execution_profile_id),
                        [],
                    )
                    decision = evaluate_placement(
                        machine=machine,
                        policy=policy,
                        execution_config=execution_config,
                        operational_status=runtime_status,
                        grant=grant,
                        profile=profile,
                        job=job,
                        unit=candidate_unit,
                        approvals=approvals,
                        solver_approval=approval,
                        active_units=active_units,
                        active_profile_units=active_profile_units,
                        pressure_settings=pressure_settings,
                        now=now,
                    )
                    if not decision.eligible:
                        continue
                    solver_variant = self._solver_for_assignment(job, unit, machine, policy, execution_approval=approval)
                    if solver_variant is None:
                        continue
                    # Origins publish sealed, validated bundles independently
                    # of plan confirmation. Hydrate only after a real machine
                    # has passed every cheap placement and capacity gate.
                    if ready_for_assignment is not None:
                        if should_continue is not None and not should_continue():
                            return None
                        hydrated, hydrated_unit = hydration.get(job.job_id, unit.work_unit_id)
                        if (
                            hydrated is None
                            or hydrated_unit is None
                            or hydrated_unit.status != WorkUnitStatus.QUEUED
                            or not ready_for_assignment(hydrated, hydrated_unit)
                        ):
                            break
                    if should_continue is not None and not should_continue():
                        return None
                    assignment_state: dict[str, str] = {}
                    attempt_resources = self._assignment_resources(
                        candidate_unit,
                        machine,
                        policy,
                        active_count=decision.occupied_slots,
                        reserved_cpus=decision.active_resources.cpus,
                        capacity=decision.effective_capacity,
                    )

                    def persist_assignment(current: JobEnvelope) -> None:
                        current_unit = next(
                            item for item in current.work_units
                            if item.work_unit_id == unit.work_unit_id
                        )
                        if current_unit.status != WorkUnitStatus.QUEUED:
                            raise _AssignmentStateChanged
                        current_unit.status = WorkUnitStatus.ASSIGNED
                        current_unit.assigned_machine_id = machine.machine_id
                        current_unit.attempt_count += 1
                        attempt_id = self._fresh_attempt_id(current_unit)
                        previous_machines = {
                            attempt.machine_id
                            for attempt in current_unit.attempts
                            if attempt.machine_id
                        }
                        current_unit.attempts.append(WorkUnitAttempt(
                            attempt_id=attempt_id,
                            machine_id=machine.machine_id,
                            assigned_at=datetime.now(timezone.utc),
                            solver_variant=solver_variant,
                            solver_approval_id=(approval.approval_id if approval else None),
                            solver_compatibility_fingerprint=(
                                approval.fingerprint if approval else None
                            ),
                            runtime_version=(approval.runtime_version if approval else None),
                            resolved_resources=attempt_resources.model_copy(deep=True),
                            pressure_state=(runtime_status.pressure_state if runtime_status else None),
                            effective_capacity=decision.effective_capacity,
                            capacity_reason=decision.capacity_reason,
                            capacity_decision_at=(runtime_status.capacity_decision_at if runtime_status else None),
                            telemetry_observed_at=(runtime_status.last_metric_at if runtime_status else None),
                            migrated=bool(
                                previous_machines
                                and machine.machine_id not in previous_machines
                            ),
                        ))
                        current.status = JobStatus.RUNNING
                        current.last_scheduled_at = datetime.now(timezone.utc)
                        assignment_state["attempt_id"] = attempt_id

                    def reserve_assignment(current: JobEnvelope) -> None:
                        from .personal_runtime import reserve_attempt
                        current_unit = next(item for item in current.work_units if item.work_unit_id == unit.work_unit_id)
                        reserve_attempt(self, current, current_unit, current_unit.attempts[-1])

                    try:
                        self.repository.mutate_job(
                            job.job_id,
                            persist_assignment,
                            before_write=reserve_assignment,
                            hydrate_blobs=False,
                        )
                    except (_AssignmentStateChanged, SharedCapacityConflict, SubmissionPolicyError, CreditError):
                        continue
                    attempt_id = assignment_state["attempt_id"]
                    assignment = Assignment(
                        job_id=job.job_id,
                        work_unit_id=unit.work_unit_id,
                        machine_id=machine.machine_id,
                        scheduler="pilot-fair-share",
                        attempt_id=attempt_id,
                        solver_variant=solver_variant,
                        solver_approval_id=approval.approval_id if approval else None,
                        solver_compatibility_fingerprint=(approval.fingerprint if approval else None),
                        runtime_version=approval.runtime_version if approval else None,
                    )
                    self._event(
                        "work_unit.assigned",
                        actor_id,
                        "work_unit",
                        unit.work_unit_id,
                        job_id=job.job_id,
                        machine_id=machine.machine_id,
                        solver_variant=solver_variant.value,
                        scheduling_strategy=scheduling.strategy,
                    )
                    return assignment
        return None


    @staticmethod
    def _dispatch_ready(unit: WorkUnit, now: datetime) -> bool:
        not_before = unit.dispatch_not_before_at
        if not_before is None:
            return True
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        return not_before <= now

    @staticmethod
    def _fresh_attempt_id(unit: WorkUnit) -> str:
        """Retry budget may exclude retired no-start Attempts; IDs never repeat."""
        serial = unit.attempt_count
        existing = {attempt.attempt_id for attempt in unit.attempts}
        candidate = f"{unit.work_unit_id}-attempt-{serial}"
        while candidate in existing:
            serial += 1
            candidate = f"{unit.work_unit_id}-attempt-{serial}"
        return candidate

    @staticmethod
    def _assignment_resources(
        unit: WorkUnit,
        machine: MachineState,
        policy: MachinePolicy,
        *,
        active_count: int,
        reserved_cpus: int = 0,
        capacity: int | None = None,
        standby: bool = False,
    ) -> ResolvedResources:
        """Freeze CPU threads and explicitly enabled observed-memory envelopes."""

        resolved = (
            unit.resolved_resources.model_copy(deep=True)
            if unit.resolved_resources is not None
            else ResolvedResources(
                resources=unit.resources.model_copy(deep=True),
                source="origin_legacy",
            )
        )
        cpu_limit = policy.effective_cpu_cap(machine.total_cpus)
        if policy.full_cpu_override is not None:
            thread_cap = policy.full_cpu_override.max_threads_per_attempt
            if thread_cap is not None:
                cpu_limit = min(cpu_limit, thread_cap)
                if max(unit.resources.cpus, resolved.resources.cpus) > cpu_limit:
                    raise ValueError("full CPU per-process cap would be exceeded")
        if unit.resource_mode != ResourceMode.DYNAMIC:
            return resolved
        if policy.full_cpu_override is not None:
            if resolved.resources.cpus > cpu_limit:
                raise ValueError("full CPU per-process cap would be exceeded")
            return resolved.model_copy(deep=True, update={
                "resources": resolved.resources.model_copy(update={"cpus": cpu_limit}),
                "source": "network_dynamic",
            })
        if policy.shared_machine:
            remaining = cpu_limit - max(0, reserved_cpus)
            floor = resolved.resources.cpus
            if floor > remaining:
                raise ValueError("shared machine CPU reserve would be exceeded")
            # Standby stays at its declared floor until the activation recheck.
            slots = max(1, capacity if capacity is not None else policy.max_concurrent_units)
            cpus = floor if standby else min(remaining, max(floor, cpu_limit // slots))
            return resolved.model_copy(deep=True, update={
                "resources": resolved.resources.model_copy(update={"cpus": cpus}),
                "source": "network_dynamic",
            })
        cpu_share = max(1, cpu_limit // (max(0, active_count) + 1))
        resources = resolved.resources.model_copy(
            update={"cpus": max(resolved.resources.cpus, cpu_share)}
        )
        return resolved.model_copy(
            deep=True,
            update={"resources": resources, "source": "network_dynamic"},
        )

    def _memory_calibrated_unit(
        self, job: JobEnvelope, unit: WorkUnit, machine: MachineState,
        policy: MachinePolicy | None, *, runtime_version: str | None,
        history_cache: dict[tuple[str, str], list[JobEnvelope]],
        execution_approval: SolverCompatibilityApproval | None = None,
    ) -> WorkUnit:
        """Use a candidate copy; scientific Units and accepted Attempts stay frozen.

        Memory is a scheduling declaration, not a solver or scientific input.
        Same-Job successful collected peaks take precedence. Cross-Job evidence
        requires the complete scientific family and the actual solver/runtime.
        In-flight samples and missing Job Object accounting never justify a
        downward adjustment. Full-CPU runs also require full-CPU evidence.
        Historical prepared launches lack verified sealed-resource evidence:
        their declared CPU count may differ from the staged request. Exclude
        them until actual launch resources are recorded and independently bound.
        """
        if (policy is None or policy.memory_peak_margin_percent is None
                or unit.resource_mode != ResourceMode.DYNAMIC
                or unit.status != WorkUnitStatus.QUEUED or not runtime_version):
            return unit
        solver = self._solver_for_assignment(
            job, unit, machine, policy,
            **({"execution_approval": execution_approval} if execution_approval is not None else {}),
        )
        if solver is None:
            return unit
        cache_key = (job.project_id, machine.machine_id)
        if cache_key not in history_cache:
            history_cache[cache_key] = self.repository.list_operational_jobs(
                project_id=job.project_id, machine_id=machine.machine_id, limit=1000,
            )
        history = [job, *(
            item for item in history_cache[cache_key] if item.job_id != job.job_id
        )]
        family_fields = (
            "project_id", "execution_profile_id", "template_sha256",
            "source_spec_sha256", "output_contract_sha256", "recipe_kind",
            "study_kind", "template_role",
        )
        strong_family = bool(job.template_sha256 and job.source_spec_sha256
                             and job.output_contract_sha256)
        same_job_peaks: list[int] = []
        family_peaks: list[int] = []
        full_cpus = (policy.effective_cpu_cap(machine.total_cpus)
                     if policy.full_cpu_override is not None else None)
        if (full_cpus is not None
                and policy.full_cpu_override.max_threads_per_attempt is not None):
            full_cpus = min(full_cpus, policy.full_cpu_override.max_threads_per_attempt)
        for sample_job in history:
            same_job = sample_job.job_id == job.job_id
            if not same_job and (
                not strong_family or any(getattr(sample_job, name) != getattr(job, name)
                                         for name in family_fields)
            ):
                continue
            for sample_unit in sample_job.work_units:
                for attempt in sample_unit.attempts:
                    frozen = attempt.resolved_resources
                    if (attempt.machine_id != machine.machine_id
                            or attempt.state != "completed"
                            or attempt.collected_at is None
                            or not attempt.execution_completed
                            or attempt.started_at is None or attempt.finished_at is None
                            or not attempt.peak_memory_mb or attempt.peak_memory_mb <= 0
                            or attempt.solver_variant != solver
                            or attempt.runtime_version != runtime_version
                            or frozen is None
                            or (full_cpus is not None and (
                                attempt.prepared or attempt.dispatch_reservation_id is not None
                                or str(attempt.external_run_id or "").startswith(
                                    f"ssh-{machine.machine_id}-reservation-"
                                )
                            ))
                            or (full_cpus is not None and frozen.resources.cpus != full_cpus)):
                        continue
                    (same_job_peaks if same_job else family_peaks).append(attempt.peak_memory_mb)
        peaks = same_job_peaks or family_peaks
        if not peaks:
            return unit
        settings = self.repository.get_feature_settings()
        resource_policy = settings.resource_policies.get(job.execution_profile_id)
        minimum = resource_policy.minimum.memory_mb if resource_policy else 256
        peak = max(peaks)
        margin = math.ceil(peak * policy.memory_peak_margin_percent / 100.0)
        resolved = (unit.resolved_resources.model_copy(deep=True)
                    if unit.resolved_resources is not None else ResolvedResources(
                        resources=unit.resources.model_copy(deep=True), source="origin_legacy",
                    ))
        resources = resolved.resources.model_copy(update={"memory_mb": max(minimum, peak + margin)})
        resolved = resolved.model_copy(deep=True, update={
            "resources": resources, "source": "network_dynamic",
            "evidence_sample_count": len(peaks), "memory_safety_margin_mb": margin,
        })
        return unit.model_copy(deep=True, update={
            "resources": resources.model_copy(deep=True), "resolved_resources": resolved,
        })

    def _machine_balance_key(
        self,
        machine_id: str,
        *,
        active_count: int,
        prepared_count: int = 0,
        policies: dict[str, MachinePolicy | None] | None = None,
        execution_configs: dict[str, MachineExecutionConfig] | None = None,
        runtime_statuses: dict[str, MachineOperationalStatus] | None = None,
    ) -> tuple[float, int, str]:
        """Order eligible machines by normalized slot occupancy.

        Counting Units alone packs work onto small-capacity machines and can
        leave a larger node under-filled.  This key uses only persisted
        capacity and reservations, never instantaneous CPU/GPU samples, so it
        cannot turn a transient telemetry dip into unsafe over-dispatch.
        """
        policy = (policies.get(machine_id) if policies is not None else self.repository.get_policy(machine_id))
        config = (execution_configs.get(machine_id) if execution_configs is not None
                  else self.repository.get_machine_execution_config(machine_id))
        runtime = (runtime_statuses.get(machine_id) if runtime_statuses is not None
                   else self.repository.get_machine_operational_status(machine_id))
        static_cap = min(
            policy.max_concurrent_units if policy is not None else 0,
            config.max_concurrent_units if config is not None else 0,
            config.target_concurrent_units if config is not None else 0,
        )
        effective_cap = min(
            static_cap,
            runtime.effective_comsol_concurrency
            if runtime is not None and runtime.effective_comsol_concurrency is not None
            else static_cap,
        )
        used = max(0, active_count) + max(0, prepared_count)
        if effective_cap <= 0:
            return (1.0, used, machine_id)
        return (used / effective_cap, used, machine_id)

    def _machine_selection_key(
        self,
        machine: MachineState,
        unit: WorkUnit,
        *,
        active_count: int,
        prepared_count: int = 0,
        job: JobEnvelope | None = None,
        history_cache: dict | None = None,
        scheduling=None,
        policies: dict[str, MachinePolicy | None] | None = None,
        execution_configs: dict[str, MachineExecutionConfig] | None = None,
        runtime_statuses: dict[str, MachineOperationalStatus] | None = None,
        approval_snapshot: _DispatchApprovalSnapshot | None = None,
    ) -> tuple[float, int, int, str]:
        """Balance slots while preserving static GPU affinity.

        Capacity remains owner-approved and is never changed from a transient
        utilization sample. The affinity tie-breaker keeps CPU-only Units off
        GPU nodes when an equivalent CPU node is available, while steering
        cuDSS-capable Units toward GPU nodes. Normalized occupancy remains the
        primary key so fairness wins over specialization when load differs.
        """
        occupancy, used, machine_id = self._machine_balance_key(
            machine.machine_id,
            active_count=active_count,
            prepared_count=prepared_count,
            **{name: value for name, value in (
                ("policies", policies), ("execution_configs", execution_configs), ("runtime_statuses", runtime_statuses),
            ) if value is not None},
        )
        has_gpu_solver = bool(
            max(
                machine.total_gpus,
                len([gpu for gpu in machine.metrics.gpu if gpu.available]),
            ) >= 1
            and "solver-cudss" in machine.capabilities
        )
        wants_gpu = SolverVariant.CUDSS in unit.allowed_solver_variants
        affinity_penalty = 0 if has_gpu_solver == wants_gpu else 1
        if job is not None:
            from .dispatch_policy import policy_for, machine_ratio
            scheduling = scheduling or policy_for(self.repository)
            if scheduling.strategy == "throughput":
                history_cache = history_cache if history_cache is not None else {}
                key = (job.project_id, machine.machine_id)
                if key not in history_cache:
                    history_cache[key] = self.repository.list_operational_jobs(
                        project_id=job.project_id, machine_id=machine.machine_id, limit=1000)
                config = (execution_configs.get(machine.machine_id) if execution_configs is not None
                          else self.repository.get_machine_execution_config(machine.machine_id))
                policy = (policies.get(machine.machine_id) if policies is not None
                          else self.repository.get_policy(machine.machine_id))
                solver = self._solver_for_assignment(
                    job, unit, machine, policy,
                    **{name: value for name, value in (
                        ("approval_snapshot", approval_snapshot), ("execution_configs", execution_configs),
                    ) if value is not None},
                )
                estimate = machine_ratio(history_cache[key], job=job, machine_id=machine.machine_id,
                    runtime_version=config.runtime_version if config else machine.runtime_version,
                    solver=solver, min_samples=scheduling.performance_min_samples,
                    requested_cpus=(min(policy.effective_cpu_cap(machine.total_cpus),
                        policy.full_cpu_override.max_threads_per_attempt or machine.total_cpus)
                        if policy and policy.full_cpu_override is not None else unit.resources.cpus))
                # Cold start keeps balanced ordering. Evidence changes only the
                # ranking, never the hard eligibility checks or solver choice.
                occupancy = (1.0 + occupancy) * (estimate["ratio"] if estimate["ratio"] is not None else 1.0)
        return (occupancy, affinity_penalty, used, machine_id)

    def defer_dispatch(
        self,
        job_id: str,
        work_unit_id: str,
        *,
        reason: str,
        actor_id: str,
    ) -> JobEnvelope:
        """Apply bounded pre-launch backoff without creating an Attempt."""

        def apply(current: JobEnvelope) -> None:
            unit = next(item for item in current.work_units if item.work_unit_id == work_unit_id)
            if unit.status != WorkUnitStatus.QUEUED:
                return
            unit.dispatch_failure_count += 1
            backoff_s = min(300, 15 * (2 ** min(unit.dispatch_failure_count - 1, 5)))
            unit.dispatch_not_before_at = datetime.now(timezone.utc) + timedelta(seconds=backoff_s)
            unit.failure_reason = reason

        updated = self.repository.mutate_job(job_id, apply, hydrate_blobs=False)
        unit = next(item for item in updated.work_units if item.work_unit_id == work_unit_id)
        self._event(
            "work_unit.dispatch_deferred",
            actor_id,
            "work_unit",
            work_unit_id,
            job_id=job_id,
            reason=reason,
            dispatch_failure_count=unit.dispatch_failure_count,
            dispatch_not_before_at=(
                unit.dispatch_not_before_at.isoformat()
                if unit.dispatch_not_before_at is not None else None
            ),
        )
        return updated

    def _solver_for_assignment(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        machine: MachineState,
        policy: MachinePolicy,
        *,
        execution_approval: SolverCompatibilityApproval | None = None,
        approval_snapshot: _DispatchApprovalSnapshot | None = None,
        execution_configs: dict[str, MachineExecutionConfig] | None = None,
    ) -> SolverVariant | None:
        latest = unit.attempts[-1] if unit.attempts else None
        cudss_failed = bool(
            latest
            and latest.solver_variant == SolverVariant.CUDSS
            and latest.state == "failed"
            and any(
                marker in str(latest.failure_reason or "").lower()
                for marker in ("cudss", "gpu runtime", "gpu unavailable")
            )
        )
        live_gpu_count = len([gpu for gpu in machine.metrics.gpu if gpu.available])
        cudss_capable = (
            max(machine.total_gpus, live_gpu_count) >= 1
            and policy.max_gpus >= 1
            and "solver-cudss" in machine.capabilities
        )
        if (
            unit.solver_policy == SolverPolicy.AUTO_FAST
            and SolverVariant.CUDSS in unit.allowed_solver_variants
            and cudss_capable
            and not cudss_failed
        ):
            try:
                approval = execution_approval or self._execution_approval_for_machine(
                    job, unit, machine,
                    **{name: value for name, value in (
                        ("approval_snapshot", approval_snapshot), ("execution_configs", execution_configs),
                    ) if value is not None},
                )
            except ExecutionCompatibilityError:
                approval = None
            if approval is not None and approval.is_active() and approval.project_id == job.project_id:
                return SolverVariant.CUDSS
        # auto_fast is capability-aware. A GPU machine receives cuDSS above;
        # a CPU-only machine may execute the same Job with MUMPS when the
        # request and approval permit it. A cuDSS-only request remains strict.
        if (
            unit.solver_policy == SolverPolicy.AUTO_FAST
            and SolverVariant.MUMPS in unit.allowed_solver_variants
        ):
            return SolverVariant.MUMPS
        if SolverVariant.MUMPS in unit.allowed_solver_variants:
            return SolverVariant.MUMPS
        return None

    @staticmethod
    def _current_attempt(unit: WorkUnit) -> WorkUnitAttempt | None:
        return unit.attempts[-1] if unit.attempts else None

    def _fenced_current_attempt(
        self, unit: WorkUnit, expected_attempt_id: str | None = None,
    ) -> WorkUnitAttempt | None:
        """A late result can never identify a successor merely by Unit ID."""
        latest = self._current_attempt(unit)
        abandoned_lineage = any(attempt.state == "abandoned" or attempt.abandonment is not None
                                for attempt in unit.attempts)
        if expected_attempt_id is None and abandoned_lineage:
            raise ValueError("expected_attempt_id is required after an Attempt was abandoned")
        if expected_attempt_id is not None and (latest is None or latest.attempt_id != expected_attempt_id):
            raise ValueError("result Attempt is no longer the current Attempt")
        if latest is not None and (latest.state == "abandoned" or latest.abandonment is not None):
            raise ValueError("an abandoned Attempt cannot publish a result")
        return latest

    @atomic_metadata
    def abandon_and_retry_unit(
        self, job_id: str, work_unit_id: str, *, expected_attempt_id: str,
        expected_external_run_id: str | None, reason: str, actor_id: str,
        operation_id: str | None = None,
    ) -> dict:
        """Explicitly discard one unknown Attempt; requeue the same immutable Unit."""
        from .models import AttemptAbandonmentRecord

        reason = reason.strip()
        if not reason or len(reason) > 1000 or not expected_attempt_id:
            raise ValueError("attempt abandonment requires an explicit identity and reason")
        operation_id = operation_id or "abandon-" + sha256_value(expected_attempt_id)[:32]
        if not operation_id.strip() or len(operation_id) > 256:
            raise ValueError("invalid abandonment operation_id")
        result: dict = {}
        applied = False

        def original_unit(current: JobEnvelope) -> WorkUnit:
            unit = next((item for item in current.work_units if item.work_unit_id == work_unit_id), None)
            if unit is None:
                raise KeyError(f"work unit not found: {work_unit_id}")
            return unit

        def replay(unit: WorkUnit) -> bool:
            original = next((item for item in unit.attempts if item.attempt_id == expected_attempt_id), None)
            record = original.abandonment if original is not None else None
            if record is None:
                return False
            if (record.operation_id != operation_id or record.reason != reason or
                    record.expected_external_run_id != expected_external_run_id):
                raise ValueError("abandonment idempotency key conflicts with the original request")
            result.update(operation_id=record.operation_id, job_id=job_id, work_unit_id=work_unit_id,
                          abandoned_attempt_id=expected_attempt_id,
                          abandoned_external_run_id=record.expected_external_run_id, outcome="replayed")
            return True

        snapshot = self.repository.get_operational_job(job_id)
        if snapshot is None:
            raise KeyError(f"job not found: {job_id}")
        if replay(original_unit(snapshot)):
            return result

        def abandon(current: JobEnvelope) -> None:
            nonlocal applied
            applied = False
            unit = original_unit(current)
            if replay(unit):
                return
            latest = self._current_attempt(unit)
            if latest is None or latest.attempt_id != expected_attempt_id or latest.external_run_id != expected_external_run_id:
                raise ValueError("current Attempt identity changed; refresh before abandoning")
            if latest.state == "abandoned" or latest.abandonment is not None:
                raise ValueError("original abandonment metadata is required")
            if any(manifest.work_unit_id == work_unit_id
                   for manifest in self.repository.list_artifact_manifests(job_id)):
                raise ValueError("a registered artifact manifest must be preserved; the Attempt cannot be abandoned")
            if unit.status in {WorkUnitStatus.COMPLETED, WorkUnitStatus.CANCELLED, WorkUnitStatus.FAILED_TERMINAL}:
                raise ValueError("a terminal WorkUnit cannot abandon an Attempt")
            unknown_states = {"uncertain", "reconcile_pending", "cancel_pending"}
            if not (latest.state in unknown_states or
                    (unit.status == WorkUnitStatus.RECONCILE_PENDING and latest.state in {"assigned", "submitting", "running"})):
                raise ValueError("only an unknown disconnected Attempt can be abandoned")
            if latest.execution_completed or latest.collected_at is not None or latest.finished_at is not None:
                raise ValueError("a positively ended Attempt cannot be abandoned as disconnected")
            if unit.attempt_count >= unit.max_attempts:
                raise ValueError("the original WorkUnit retry budget is exhausted")
            if any(item.abandonment is not None and item.abandonment.operation_id == operation_id
                   for candidate in current.work_units for item in candidate.attempts):
                raise ValueError("abandonment operation_id already belongs to another Attempt")
            latest.abandonment = AttemptAbandonmentRecord(
                operation_id=operation_id, actor_id=actor_id, reason=reason,
                abandoned_at=datetime.now(timezone.utc), expected_attempt_id=expected_attempt_id,
                expected_external_run_id=expected_external_run_id,
            )
            latest.state = "abandoned"
            # This is an administrator's result-custody decision, not evidence
            # that the original remote process ended or stopped.
            unit.status = WorkUnitStatus.QUEUED
            unit.assigned_machine_id = None
            unit.failure_reason = None
            unit.actual_duration_s = None
            unit.progress_percent = 0.0
            unit.completed_items = 0
            unit.eta_s = None
            unit.progress_message = "original Attempt abandoned by administrator; queued for retry"
            current.status = derived_job_status(current)
            applied = True
            result.update(operation_id=operation_id, job_id=job_id, work_unit_id=work_unit_id,
                          abandoned_attempt_id=expected_attempt_id,
                          abandoned_external_run_id=expected_external_run_id, outcome="queued")

        self.repository.mutate_job(job_id, abandon, hydrate_blobs=False)
        if applied:
            self._event("work_unit.attempt_abandoned", actor_id, "work_unit", work_unit_id,
                        job_id=job_id, attempt_id=expected_attempt_id, external_run_id=expected_external_run_id,
                        operation_id=operation_id, reason=reason)
        return result

    @staticmethod
    def _terminal_job_status(job: JobEnvelope) -> JobStatus | None:
        return derived_job_status(job) if job.work_units else None

    def reconcile_terminal_job_statuses(self, *, actor_id: str) -> int:
        """Repair stale Job summaries from current Unit and Attempt truth."""
        changed_total = 0
        for snapshot in self.repository.list_operational_jobs(statuses={
            JobStatus.AWAITING_APPROVAL,
            JobStatus.QUEUED,
            JobStatus.RUNNING,
            JobStatus.FAILED_RETRIABLE,
            JobStatus.FAILED_TERMINAL,
        }):
            target = self._terminal_job_status(snapshot)
            if target is None or snapshot.status == target:
                continue
            change = {"previous": None, "current": None}

            def apply_status(current: JobEnvelope) -> None:
                current_target = self._terminal_job_status(current)
                if current_target is None or current.status == current_target:
                    return
                change["previous"] = current.status
                current.status = current_target
                change["current"] = current_target

            self.repository.mutate_job(
                snapshot.job_id,
                apply_status,
                hydrate_blobs=False,
            )
            if change["current"] is None:
                continue
            changed_total += 1
            self._event(
                "job.terminal_status_reconciled",
                actor_id,
                "job",
                snapshot.job_id,
                previous_status=change["previous"].value,
                status=change["current"].value,
            )
        return changed_total

    def reconcile_registered_manifests(self, *, actor_id: str) -> int:
        """Treat a validated, registered manifest as authoritative completion evidence."""
        changed_total = 0
        for snapshot in self.repository.list_operational_jobs(statuses={
            JobStatus.AWAITING_APPROVAL,
            JobStatus.QUEUED,
            JobStatus.RUNNING,
            JobStatus.FAILED_RETRIABLE,
            JobStatus.FAILED_TERMINAL,
        }):
            manifests = {
                manifest.work_unit_id: manifest
                for manifest in self.repository.list_artifact_manifests(snapshot.job_id)
            }
            for unit in snapshot.work_units:
                manifest = manifests.get(unit.work_unit_id)
                if manifest is None or unit.status == WorkUnitStatus.COMPLETED:
                    continue
                producer_id = manifest.producer.get("attempt_id")
                latest = self._current_attempt(unit)
                # Timestamps cannot establish producer identity after retry.
                # Preserve only the unambiguous legacy zero/single-Attempt case.
                if producer_id:
                    if latest is None or latest.attempt_id != producer_id:
                        continue
                elif len(unit.attempts) > 1 or any(
                    item.state == "abandoned" or item.abandonment is not None for item in unit.attempts
                ):
                    continue
                attempt = latest
                if attempt is not None and (attempt.state == "abandoned" or attempt.abandonment is not None):
                    continue
                producer_run = manifest.producer.get("external_run_id")
                if producer_run and (attempt is None or producer_run != attempt.external_run_id):
                    continue
                duration_s = unit.actual_duration_s or 0.0
                if attempt is not None and attempt.started_at is not None:
                    duration_s = max(
                        duration_s,
                        (manifest.created_at - attempt.started_at).total_seconds(),
                    )
                try:
                    completed = self.mark_unit_completed(
                        snapshot.job_id, unit.work_unit_id, duration_s=duration_s, actor_id=actor_id,
                        expected_attempt_id=attempt.attempt_id if attempt is not None else None,
                    )
                except ValueError:
                    # A concurrent administrative abandonment won the CAS.
                    continue
                if not any(item.work_unit_id == unit.work_unit_id and item.status == WorkUnitStatus.COMPLETED
                           for item in completed.work_units):
                    continue
                changed_total += 1
                self._event(
                    "work_unit.registered_manifest_reconciled",
                    actor_id,
                    "work_unit",
                    unit.work_unit_id,
                    job_id=snapshot.job_id,
                    attempt_id=attempt.attempt_id if attempt is not None else None,
                    manifest_created_at=manifest.created_at.isoformat(),
                )
        return changed_total

    def _confirmed_failed_remote_attempt(self, attempt, unit, job_id=None) -> bool:
        """Positive terminal evidence, never a missing heartbeat or timeout.

        The supervisor only publishes FAILED after its worker exits. A result
        or successful execution is reconciled/collected, never recomputed.
        """
        if (attempt.state != "failed" or not attempt.external_run_id
                or attempt.execution_completed or attempt.collected_at is not None):
            return False
        run = self.repository.get_remote_run(attempt.external_run_id)
        if not run or not (
            run.state == RemoteRunState.FAILED
            and run.machine_id == attempt.machine_id
            and run.work_unit_id == unit.work_unit_id
            and (job_id is None or run.job_id == job_id)
            and not run.artifacts_available
        ):
            return False
        return not any(
            manifest.work_unit_id == unit.work_unit_id
            for manifest in self.repository.list_artifact_manifests(run.job_id)
        )

    def _recoverable_storage_terminal(self, unit, job_id) -> bool:
        attempt = self._current_attempt(unit)
        if attempt is None or unit.status != WorkUnitStatus.FAILED_TERMINAL:
            return False
        reason = attempt.failure_reason or unit.failure_reason or ""
        return bool(
            unit.attempt_count < unit.max_attempts
            and (is_native_file_io_failure(reason) or is_storage_exhaustion_failure(reason))
            and self._confirmed_failed_remote_attempt(attempt, unit, job_id)
        )

    def _attempt_retry_evidence_clear(self, attempt, unit) -> bool:
        """Whether persisted attempt evidence permits an automatic bounded retry.

        Evidence qualifies when no execution started, a deterministic console
        termination is known, or a positively observed failed remote run has
        no completed execution/result and is classified as environment failure.

        - the attempt never started executing, so no remote boundary was
          crossed and no scientific work can be duplicated;
        - the failure reason carries a deterministic worker-termination exit
          code (e.g. 0xC000013A): the worker's console was torn down with its
          transport session, the process is confirmed dead and produced no
          result, so reusing the same work_unit_id keeps the no-duplicate
          scientific-work guarantees intact.
        """
        reason = str(attempt.failure_reason or unit.failure_reason or "")
        if attempt.execution_completed or attempt.collected_at is not None:
            return False
        if attempt.execution_started and not is_worker_termination_failure(reason):
            return bool(
                attempt.failure_class in {FailureClass.INFRASTRUCTURE, FailureClass.RESOURCE_EXHAUSTION}
                and self._confirmed_failed_remote_attempt(attempt, unit)
            )
        return True

    def _auto_retry_failed_units(self, *, actor_id: str) -> int:
        """Queue only infrastructure failures for bounded migration."""
        changed_total = 0
        for snapshot in self.repository.list_operational_jobs(statuses={
            JobStatus.QUEUED,
            JobStatus.RUNNING,
            JobStatus.FAILED_RETRIABLE,
            JobStatus.FAILED_TERMINAL,
        }):
            retryable_snapshot = [
                unit for unit in snapshot.work_units
                if unit.status == WorkUnitStatus.FAILED_RETRIABLE
                and (attempt := self._current_attempt(unit)) is not None
                and self._attempt_retry_evidence_clear(attempt, unit)
                and not (
                    attempt.external_run_id
                    and str(attempt.failure_reason or unit.failure_reason or "").startswith(
                        "remote state remained uncertain:"
                    )
                )
                and (
                    attempt.failure_class in {
                        FailureClass.INFRASTRUCTURE,
                        FailureClass.RESOURCE_EXHAUSTION,
                    }
                    or is_worker_termination_failure(
                        attempt.failure_reason or unit.failure_reason or ""
                    )
                )
            ]
            if not retryable_snapshot:
                continue
            retry_state = {"changed": 0}

            def apply_retry(current: JobEnvelope) -> None:
                retry_state["changed"] = 0
                for unit in current.work_units:
                    if unit.status != WorkUnitStatus.FAILED_RETRIABLE:
                        continue
                    attempt = self._current_attempt(unit)
                    if attempt is None or not (
                        attempt.failure_class in {
                            FailureClass.INFRASTRUCTURE,
                            FailureClass.RESOURCE_EXHAUSTION,
                        }
                        or is_worker_termination_failure(
                            attempt.failure_reason or unit.failure_reason or ""
                        )
                    ):
                        continue
                    if not self._attempt_retry_evidence_clear(attempt, unit) or (
                        attempt.external_run_id
                        and str(attempt.failure_reason or unit.failure_reason or "").startswith(
                            "remote state remained uncertain:"
                        )
                    ):
                        continue
                    if unit.attempt_count >= unit.max_attempts:
                        unit.status = WorkUnitStatus.FAILED_TERMINAL
                        continue
                    unit.status = WorkUnitStatus.QUEUED
                    unit.assigned_machine_id = None
                    unit.actual_duration_s = None
                    unit.failure_reason = None
                    retry_state["changed"] += 1
                terminal_states = {
                    WorkUnitStatus.COMPLETED,
                    WorkUnitStatus.FAILED_TERMINAL,
                    WorkUnitStatus.CANCELLED,
                }
                if all(unit.status == WorkUnitStatus.COMPLETED for unit in current.work_units):
                    current.status = JobStatus.COMPLETED
                elif any(
                    unit.status in {
                        WorkUnitStatus.QUEUED,
                        WorkUnitStatus.ASSIGNED,
                        WorkUnitStatus.RUNNING,
                    }
                    for unit in current.work_units
                ):
                    current.status = JobStatus.QUEUED
                elif all(unit.status in terminal_states for unit in current.work_units):
                    current.status = (
                        JobStatus.CANCELLED
                        if any(
                            unit.status == WorkUnitStatus.CANCELLED
                            for unit in current.work_units
                        )
                        else JobStatus.FAILED_TERMINAL
                    )

            self.repository.mutate_job(
                snapshot.job_id,
                apply_retry,
                hydrate_blobs=False,
            )
            changed = retry_state["changed"]
            if changed:
                changed_total += changed
                self._event(
                    "job.auto_retried",
                    actor_id,
                    "job",
                    snapshot.job_id,
                    attempts=changed,
                )
        return changed_total

    def _reclassify_unknown_scientific_failures(self, *, actor_id: str) -> int:
        """Correct legacy unknown failures when persisted evidence is deterministic.

        This runs before automatic retry and only changes failed Attempts that
        already crossed the scientific execution boundary. It never launches,
        retries, or mutates scientific payloads.
        """

        changed_total = 0
        statuses = {
            JobStatus.QUEUED,
            JobStatus.RUNNING,
            JobStatus.FAILED_RETRIABLE,
        }
        if not self._unknown_failure_backfill_complete:
            statuses.add(JobStatus.FAILED_TERMINAL)
        snapshots = self.repository.list_operational_jobs(statuses=statuses)
        self._unknown_failure_backfill_complete = True
        for snapshot in snapshots:
            candidates = {
                unit.work_unit_id
                for unit in snapshot.work_units
                if unit.attempts
                and unit.attempts[-1].state == "failed"
                and unit.attempts[-1].failure_class == FailureClass.UNKNOWN
                and unit.attempts[-1].execution_started
                and is_deterministic_scientific_failure(
                    unit.attempts[-1].failure_reason or unit.failure_reason or ""
                )
            }
            if not candidates:
                continue
            changed_ids: list[str] = []

            def apply_reclassification(current: JobEnvelope) -> None:
                changed_ids.clear()
                for unit in current.work_units:
                    if unit.work_unit_id not in candidates or not unit.attempts:
                        continue
                    attempt = unit.attempts[-1]
                    evidence = attempt.failure_reason or unit.failure_reason or ""
                    if not (
                        attempt.state == "failed"
                        and attempt.failure_class == FailureClass.UNKNOWN
                        and attempt.execution_started
                        and is_deterministic_scientific_failure(evidence)
                    ):
                        continue
                    attempt.failure_class = FailureClass.SCIENTIFIC_INPUT
                    unit.status = WorkUnitStatus.FAILED_TERMINAL
                    changed_ids.append(unit.work_unit_id)
                if changed_ids:
                    current.status = derived_job_status(current)

            self.repository.mutate_job(
                snapshot.job_id,
                apply_reclassification,
                hydrate_blobs=False,
            )
            for work_unit_id in changed_ids:
                changed_total += 1
                self._event(
                    "work_unit.failure_reclassified",
                    actor_id,
                    "work_unit",
                    work_unit_id,
                    job_id=snapshot.job_id,
                    previous_failure_class=FailureClass.UNKNOWN.value,
                    failure_class=FailureClass.SCIENTIFIC_INPUT.value,
                    reason_code="deterministic_scientific_evaluation_failure",
                )
        return changed_total

    def _apply_unit_completion(
        self, job: JobEnvelope, work_unit_id: str, *, duration_s: float,
        expected_attempt_id: str | None,
    ) -> bool:
        unit = next((candidate for candidate in job.work_units if candidate.work_unit_id == work_unit_id), None)
        if unit is None:
            raise KeyError(f"work unit not found: {work_unit_id}")
        attempt = self._fenced_current_attempt(unit, expected_attempt_id)
        if (job.status == JobStatus.CANCELLED or unit.status == WorkUnitStatus.CANCELLED or
                (attempt is not None and (attempt.state in {"cancel_pending", "cancelled"} or
                                          attempt.cancel_requested_at is not None))):
            return False
        unit.status = WorkUnitStatus.COMPLETED
        unit.failure_reason = None
        unit.actual_duration_s = duration_s
        if unit.total_items is None and unit.atomic_item_ids:
            unit.total_items = len(unit.atomic_item_ids)
        unit.progress_percent = 100.0
        unit.completed_items = unit.total_items
        unit.eta_s = 0.0
        unit.progress_message = "outputs ready"
        if attempt is not None:
            attempt.state = "completed"
            attempt.finished_at = datetime.now(timezone.utc)
            attempt.failure_reason = None
            attempt.failure_class = None
        terminal_status = self._terminal_job_status(job)
        if terminal_status is not None:
            job.status = terminal_status
        return True

    @settle_after
    def mark_unit_completed(
        self,
        job_id: str,
        work_unit_id: str,
        *,
        duration_s: float,
        actor_id: str,
        attempt_id: str | None = None,
        expected_attempt_id: str | None = None,
    ) -> JobEnvelope:
        if expected_attempt_id is not None and attempt_id is not None and expected_attempt_id != attempt_id:
            raise ValueError("completion Attempt declarations disagree")
        identity = expected_attempt_id or attempt_id
        completion_applied = False

        def apply_completion(job: JobEnvelope) -> None:
            nonlocal completion_applied
            completion_applied = False
            completion_applied = self._apply_unit_completion(
                job, work_unit_id, duration_s=duration_s, expected_attempt_id=identity,
            )

        job = self.repository.mutate_job(
            job_id,
            apply_completion,
            hydrate_blobs=False,
        )
        if completion_applied:
            self._event("work_unit.completed", actor_id, "work_unit", work_unit_id, job_id=job_id)
        return job

    def mark_unit_started(self, job_id: str, work_unit_id: str, *, actor_id: str,
                          expected_attempt_id: str | None = None) -> JobEnvelope:
        def start(current: JobEnvelope) -> None:
            unit = next((candidate for candidate in current.work_units if candidate.work_unit_id == work_unit_id), None)
            if unit is None:
                raise KeyError(f"work unit not found: {work_unit_id}")
            attempt = self._fenced_current_attempt(unit, expected_attempt_id)
            if unit.status != WorkUnitStatus.ASSIGNED:
                raise ValueError(f"work unit must be assigned before start, got {unit.status.value}")
            unit.status = WorkUnitStatus.RUNNING
            current.status = JobStatus.RUNNING
            if attempt is not None:
                attempt.state = "running"
                attempt.started_at = datetime.now(timezone.utc)
        job = self.repository.mutate_job(job_id, start, hydrate_blobs=False)
        self._event("work_unit.started", actor_id, "work_unit", work_unit_id, job_id=job_id)
        return job

    @settle_after
    def complete_unit(
        self,
        job_id: str,
        work_unit_id: str,
        *,
        manifest: ArtifactManifest,
        duration_s: float,
        actor_id: str,
        attempt_id: str | None = None,
        expected_attempt_id: str | None = None,
    ) -> JobEnvelope:
        if manifest.job_id != job_id or manifest.work_unit_id != work_unit_id:
            raise ValueError("artifact manifest identity does not match the completed work unit")
        if expected_attempt_id is not None and attempt_id is not None and expected_attempt_id != attempt_id:
            raise ValueError("completion Attempt declarations disagree")
        identity = expected_attempt_id or attempt_id or manifest.producer.get("attempt_id")
        if manifest.producer.get("attempt_id") and manifest.producer["attempt_id"] != identity:
            raise ValueError("manifest producer does not match the completion Attempt")
        job = self.repository.get_operational_job(job_id)
        if job is None:
            raise KeyError(f"job not found: {job_id}")
        unit = next((candidate for candidate in job.work_units if candidate.work_unit_id == work_unit_id), None)
        if unit is None:
            raise KeyError(f"work unit not found: {work_unit_id}")
        profile = self.repository.get_profile(job.execution_profile_id)
        if profile is None:
            raise ValueError(f"unknown execution profile: {job.execution_profile_id}")
        if manifest.output_schema != profile.output_schema:
            raise ValueError(
                "artifact manifest output schema does not match the execution profile"
            )
        output_mb = (
            sum(record.size_bytes for record in manifest.files) + 1024**2 - 1
        ) // 1024**2
        completion_applied = False

        def complete(current: JobEnvelope) -> bool:
            nonlocal completion_applied
            completion_applied = False
            current_unit = next(item for item in current.work_units if item.work_unit_id == work_unit_id)
            attempt = self._fenced_current_attempt(current_unit, identity)
            if any(item.abandonment is not None or item.state == "abandoned" for item in current_unit.attempts):
                if not manifest.producer.get("attempt_id"):
                    raise ValueError("manifest producer Attempt identity is required after abandonment")
            if current_unit.status not in {WorkUnitStatus.ASSIGNED, WorkUnitStatus.RUNNING, WorkUnitStatus.COLLECTING}:
                raise ValueError(f"work unit cannot complete from {current_unit.status.value}")
            producer_run = manifest.producer.get("external_run_id")
            if producer_run and (attempt is None or producer_run != attempt.external_run_id):
                raise ValueError("manifest producer remote run does not match the current Attempt")
            if not self._apply_unit_completion(current, work_unit_id, duration_s=duration_s,
                                               expected_attempt_id=identity):
                return False
            if attempt is not None:
                attempt.peak_disk_mb = max(attempt.peak_disk_mb or 0, output_mb)
                attempt.execution_completed = True
            completion_applied = True
            return True

        completed = self.repository.mutate_job_with_artifact_manifest(
            job_id, manifest, complete,
        )
        if completion_applied:
            self._event("work_unit.completed", actor_id, "work_unit", work_unit_id, job_id=job_id)
            self._adapt_resource_policy(completed.execution_profile_id, actor_id=actor_id)
        return completed

    def _adapt_resource_policy(self, profile_id: str, *, actor_id: str) -> None:
        settings = self.repository.get_feature_settings()
        policy = settings.resource_policies.get(profile_id)
        if policy is None or not policy.automatic_adjustment:
            return
        successful = [
            attempt
            for job in self.repository.list_operational_jobs(limit=1000)
            if job.execution_profile_id == profile_id
            for unit in job.work_units
            for attempt in unit.attempts
            if attempt.state == "completed"
            and attempt.peak_memory_mb is not None
            and attempt.peak_disk_mb is not None
        ]
        updated, resolved = recommend_adaptive_policy(
            policy,
            memory_peak_mb=[attempt.peak_memory_mb for attempt in successful],
            disk_peak_mb=[attempt.peak_disk_mb for attempt in successful],
        )
        if updated.revision == policy.revision:
            return
        settings.resource_policies[profile_id] = updated
        settings.updated_at = datetime.now(timezone.utc)
        self.repository.put_feature_settings(settings)
        self._event(
            "resource_policy.adapted",
            actor_id,
            "execution_profile",
            profile_id,
            revision=updated.revision,
            evidence_sample_count=resolved.evidence_sample_count,
            baseline=updated.baseline.model_dump(mode="json"),
        )

    def record_origin_import(
        self,
        receipt: OriginImportReceipt,
        *,
        actor_id: str,
    ) -> OriginImportReceipt:
        job = self.repository.get_job(receipt.job_id)
        if job is None:
            raise KeyError(f"job not found: {receipt.job_id}")
        if receipt.imported_by != actor_id:
            raise ValueError("origin import receipt actor does not match the authenticated user")
        if receipt.request_hash != job.request_hash:
            raise ValueError("origin import receipt request hash does not match the Job")
        if receipt.campaign_id != job.campaign_id or receipt.campaign_task_id != job.campaign_task_id:
            raise ValueError("origin import receipt campaign identity does not match the Job")
        manifests = sorted(
            self.repository.list_artifact_manifests(job.job_id),
            key=lambda item: item.work_unit_id,
        )
        registered_ids = {manifest.work_unit_id for manifest in manifests}
        unit_ids = {unit.work_unit_id for unit in job.work_units}
        if not registered_ids <= unit_ids:
            raise ValueError("registered artifact manifests reference WorkUnits outside the Job")
        imported_ids: list[str] | None
        missing_ids: list[str] | None
        if receipt.import_mode == "complete":
            if job.status != JobStatus.COMPLETED:
                raise ValueError("only a completed Job can receive a complete origin import receipt")
            if len(manifests) != len(job.work_units):
                raise ValueError("origin import receipt requires one manifest per WorkUnit")
            if receipt.imported_work_unit_ids is not None or receipt.missing_work_unit_ids is not None:
                raise ValueError("a complete origin import receipt must not declare partial WorkUnit ledgers")
            if receipt.work_unit_count is not None and receipt.work_unit_count != len(job.work_units):
                raise ValueError("complete receipt WorkUnit count does not match the Job ledger")
            imported_ids = None
            missing_ids = None
        else:
            if job.status not in {JobStatus.FAILED_TERMINAL, JobStatus.CANCELLED}:
                raise ValueError(
                    "a partial origin import receipt requires a terminal failed_terminal or cancelled Job"
                )
            if receipt.imported_work_unit_ids is None or not receipt.imported_work_unit_ids:
                raise ValueError("a partial origin import receipt must declare its imported WorkUnits")
            imported_ids = sorted(set(receipt.imported_work_unit_ids))
            if len(imported_ids) != len(receipt.imported_work_unit_ids):
                raise ValueError("a partial origin import receipt must not repeat imported WorkUnits")
            if set(imported_ids) != registered_ids:
                raise ValueError(
                    "partial receipt imported WorkUnits do not match the registered artifact manifests"
                )
            active_ids = {
                unit.work_unit_id
                for unit in job.work_units
                if unit.status
                in {
                    WorkUnitStatus.QUEUED,
                    WorkUnitStatus.ASSIGNED,
                    WorkUnitStatus.RUNNING,
                    WorkUnitStatus.RECONCILE_PENDING,
                    WorkUnitStatus.COLLECTING,
                }
            }
            if active_ids:
                raise ValueError(
                    "a partial origin import receipt requires a Job with no active WorkUnits"
                )
            derived_missing = sorted(unit_ids - registered_ids)
            if receipt.missing_work_unit_ids is None or sorted(
                set(receipt.missing_work_unit_ids)
            ) != derived_missing or len(receipt.missing_work_unit_ids) != len(derived_missing):
                raise ValueError(
                    "partial receipt missing WorkUnits do not match the Job ledger"
                )
            if receipt.work_unit_count is not None and receipt.work_unit_count != len(job.work_units):
                raise ValueError("partial receipt WorkUnit count does not match the Job ledger")
            missing_ids = derived_missing
        summary = sha256_value([item.model_dump(mode="json") for item in manifests])
        if receipt.manifest_summary_sha256 != summary:
            raise ValueError("origin import receipt manifest summary does not match the Job")
        existing = self.repository.get_origin_import_receipt(job.job_id)
        if existing is not None:
            if existing.model_dump(mode="json") != receipt.model_dump(mode="json"):
                raise ValueError("Job already has a different origin import receipt")
            return existing
        # Complete receipts persist verbatim for byte-compatibility with the
        # historical contract; partial receipts persist the server-derived
        # WorkUnit ledger so the stored evidence cannot drift from the Job.
        if receipt.import_mode == "partial":
            receipt = receipt.model_copy(
                update={
                    "work_unit_count": len(job.work_units),
                    "imported_work_unit_ids": imported_ids,
                    "missing_work_unit_ids": missing_ids,
                }
            )
        self.repository.put_origin_import_receipt(receipt)
        self._event(
            "origin.import_recorded",
            actor_id,
            "job",
            job.job_id,
            dataset_id=receipt.dataset_id,
            campaign_id=job.campaign_id,
            campaign_task_id=job.campaign_task_id,
            import_mode=receipt.import_mode,
            imported_work_unit_count=len(imported_ids) if imported_ids is not None else len(manifests),
            missing_work_unit_count=len(missing_ids) if missing_ids is not None else 0,
        )
        return receipt

    @settle_after
    def fail_unit(
        self,
        job_id: str,
        work_unit_id: str,
        *,
        error: str,
        retryable: bool | None = None,
        failure_class: FailureClass | None = None,
        actor_id: str,
        expected_attempt_id: str | None = None,
    ) -> JobEnvelope:
        if failure_class is None:
            if retryable is None:
                failure_class = FailureClass.UNKNOWN
            else:
                failure_class = (
                    FailureClass.INFRASTRUCTURE if retryable else FailureClass.SCIENTIFIC_INPUT
                )
        if (
            failure_class == FailureClass.UNKNOWN
            and is_deterministic_scientific_failure(error)
        ):
            failure_class = FailureClass.SCIENTIFIC_INPUT
        from .failure_diagnostics import is_memory_exhaustion_failure
        from .failure_policy import failure_advice
        if failure_class == FailureClass.UNKNOWN and is_memory_exhaustion_failure(error):
            failure_class = FailureClass.RESOURCE_EXHAUSTION
        resolved_failure_class = failure_class
        failure_applied = False

        def apply_failure(job: JobEnvelope) -> None:
            nonlocal failure_applied
            failure_applied = False
            unit = next(
                (candidate for candidate in job.work_units if candidate.work_unit_id == work_unit_id),
                None,
            )
            if unit is None:
                raise KeyError(f"work unit not found: {work_unit_id}")
            attempt = self._fenced_current_attempt(unit, expected_attempt_id)
            if job.status == JobStatus.CANCELLED or unit.status == WorkUnitStatus.CANCELLED:
                return
            allowed_failure_states = {
                WorkUnitStatus.ASSIGNED,
                WorkUnitStatus.RUNNING,
                WorkUnitStatus.RECONCILE_PENDING,
                WorkUnitStatus.COLLECTING,
            }
            if resolved_failure_class == FailureClass.CANCELLED:
                allowed_failure_states.add(WorkUnitStatus.CANCELLED)
            if unit.status not in allowed_failure_states:
                raise ValueError(f"work unit cannot fail from {unit.status.value}")
            if resolved_failure_class == FailureClass.CANCELLED:
                unit.status = WorkUnitStatus.CANCELLED
            elif resolved_failure_class in {
                FailureClass.INFRASTRUCTURE,
                FailureClass.RESOURCE_EXHAUSTION,
                FailureClass.UNKNOWN,
            }:
                unit.status = WorkUnitStatus.FAILED_RETRIABLE
            else:
                unit.status = WorkUnitStatus.FAILED_TERMINAL
            unit.failure_reason = error
            if attempt is not None:
                attempt.state = "failed"
                attempt.finished_at = datetime.now(timezone.utc)
                attempt.failure_reason = error
                attempt.failure_class = resolved_failure_class
            if resolved_failure_class == FailureClass.CANCELLED:
                job.status = JobStatus.CANCELLED
            elif resolved_failure_class in {
                FailureClass.INFRASTRUCTURE,
                FailureClass.RESOURCE_EXHAUSTION,
                FailureClass.UNKNOWN,
            }:
                job.status = JobStatus.FAILED_RETRIABLE
            else:
                job.status = JobStatus.FAILED_TERMINAL
            failure_applied = True

        job = self.repository.mutate_job(
            job_id,
            apply_failure,
            hydrate_blobs=False,
        )
        if failure_applied and resolved_failure_class == FailureClass.RESOURCE_EXHAUSTION:
            self._upshift_resource_policy_after_failure(
                job,
                work_unit_id,
                error=error,
                actor_id=actor_id,
            )
        if failure_applied:
            self._event(
                "work_unit.failed",
                actor_id,
                "work_unit",
                work_unit_id,
                job_id=job_id,
                retryable=resolved_failure_class in {
                    FailureClass.INFRASTRUCTURE,
                    FailureClass.RESOURCE_EXHAUSTION,
                },
                failure_class=resolved_failure_class.value,
                error=error,
                recovery_advice=failure_advice(error, reported_class=resolved_failure_class),
            )
        return job

    def set_job_placement(
        self,
        job_id: str,
        placement: PlacementConstraint,
        *,
        actor_id: str,
        allow_required: bool,
    ) -> JobEnvelope:
        if placement.required_machine_id and not allow_required:
            raise PermissionError("required-machine placement is restricted to administrators")
        target = placement.required_machine_id or placement.preferred_machine_id
        if target and self.repository.get_machine(target) is None:
            raise KeyError(f"machine not found: {target}")
        placement.requested_by = actor_id
        placement.updated_at = datetime.now(timezone.utc)

        def apply(job: JobEnvelope) -> None:
            if job.status not in {JobStatus.AWAITING_APPROVAL, JobStatus.QUEUED}:
                raise ValueError("placement can only change before a work unit is assigned")
            job.placement = placement

        job = self.repository.mutate_job(job_id, apply, hydrate_blobs=False)
        self._event(
            "job.placement_updated",
            actor_id,
            "job",
            job_id,
            preferred_machine_id=placement.preferred_machine_id,
            required_machine_id=placement.required_machine_id,
            reason=placement.reason,
        )
        return job

    def retry(self, job_id: str, *, actor_id: str) -> JobEnvelope:
        job = self.repository.get_job(job_id)
        if job is None:
            raise KeyError(f"job not found: {job_id}")
        if job.status != JobStatus.FAILED_RETRIABLE:
            raise ValueError(f"job is not retryable from status {job.status.value}")
        for unit in job.work_units:
            if unit.status == WorkUnitStatus.FAILED_RETRIABLE:
                if unit.attempt_count >= unit.max_attempts:
                    unit.status = WorkUnitStatus.FAILED_TERMINAL
                    continue
                unit.status = WorkUnitStatus.QUEUED
                unit.assigned_machine_id = None
                unit.actual_duration_s = None
                unit.failure_reason = None
        if all(unit.status in {WorkUnitStatus.COMPLETED, WorkUnitStatus.FAILED_TERMINAL} for unit in job.work_units):
            job.status = JobStatus.FAILED_TERMINAL
        else:
            job.status = JobStatus.QUEUED
        self.repository.put_job(job)
        self._event("job.retried", actor_id, "job", job_id)
        return job

    def _retry_cancelled_unit(
        self,
        job_id: str,
        work_unit_id: str,
        *,
        actor_id: str,
    ) -> JobEnvelope:
        """Atomically requeue one acknowledged cancellation without rewriting science."""
        retried = False
        exhausted = False

        def apply_retry(job: JobEnvelope) -> None:
            nonlocal retried, exhausted
            # mutate_job may invoke this again after another Unit advances the
            # aggregate revision. Only the successful invocation emits an event.
            retried = False
            exhausted = False
            unit = next(
                (item for item in job.work_units if item.work_unit_id == work_unit_id),
                None,
            )
            if unit is None:
                raise KeyError(f"work unit not found: {work_unit_id}")
            if unit.status != WorkUnitStatus.CANCELLED:
                raise ValueError(f"work unit is not retryable from status {unit.status.value}")
            if any(
                attempt.state in self._REASSIGN_ACTIVE_ATTEMPT_STATES
                for attempt in unit.attempts
            ):
                raise ValueError("work unit cancellation acknowledgment is still pending")
            latest = unit.attempts[-1] if unit.attempts else None
            if latest is not None and latest.external_run_id is not None and (
                latest.state != "cancelled" or latest.finished_at is None
            ):
                raise ValueError("remote work unit cancellation acknowledgment is incomplete")
            other_work_is_active = any(
                candidate.work_unit_id != work_unit_id
                and candidate.status in {
                    WorkUnitStatus.ASSIGNED,
                    WorkUnitStatus.RUNNING,
                    WorkUnitStatus.RECONCILE_PENDING,
                    WorkUnitStatus.COLLECTING,
                }
                for candidate in job.work_units
            )
            if unit.attempt_count >= unit.max_attempts:
                unit.status = WorkUnitStatus.FAILED_TERMINAL
                job.status = JobStatus.RUNNING if other_work_is_active else JobStatus.FAILED_TERMINAL
                exhausted = True
                return
            unit.status = WorkUnitStatus.QUEUED
            unit.assigned_machine_id = None
            unit.actual_duration_s = None
            unit.progress_percent = 0.0
            unit.dispatch_not_before_at = None
            unit.dispatch_failure_count = 0
            unit.failure_reason = None
            job.status = JobStatus.RUNNING if other_work_is_active else JobStatus.QUEUED
            retried = True

        job = self.repository.mutate_job(job_id, apply_retry, hydrate_blobs=False)
        if exhausted:
            raise ValueError("work unit has exhausted its retry limit")
        if retried:
            self._event("work_unit.retried", actor_id, "work_unit", work_unit_id, job_id=job_id)
        return job

    def retry_unit(
        self,
        job_id: str,
        work_unit_id: str,
        *,
        actor_id: str,
        allow_cancelled: bool = False,
    ) -> JobEnvelope:
        """Requeue one bounded failed unit and permit migration on retry."""
        if allow_cancelled:
            snapshot = self.repository.get_operational_job(job_id)
            if snapshot is None:
                raise KeyError(f"job not found: {job_id}")
            snapshot_unit = next(
                (item for item in snapshot.work_units if item.work_unit_id == work_unit_id),
                None,
            )
            if snapshot_unit is None:
                raise KeyError(f"work unit not found: {work_unit_id}")
            if snapshot_unit.status == WorkUnitStatus.CANCELLED:
                return self._retry_cancelled_unit(job_id, work_unit_id, actor_id=actor_id)
        job = self.repository.get_job(job_id)
        if job is None:
            raise KeyError(f"job not found: {job_id}")
        unit = next((item for item in job.work_units if item.work_unit_id == work_unit_id), None)
        if unit is None:
            raise KeyError(f"work unit not found: {work_unit_id}")
        # A cancellation can arrive after the initial operational read. It must
        # still pass the atomic acknowledgment gate rather than the legacy retry.
        if allow_cancelled and unit.status == WorkUnitStatus.CANCELLED:
            return self._retry_cancelled_unit(job_id, work_unit_id, actor_id=actor_id)
        latest_attempt = unit.attempts[-1] if unit.attempts else None
        prelaunch_remote_allowlist_failure = bool(
            latest_attempt is not None
            # A sealed supervisor can reject an origin bundle after the
            # remote-run ID is allocated but before any COMSOL process starts.
            # This exact failure is recoverable after a verified runtime
            # promotion; other remote failures must retain the no-duplicate
            # scientific-work boundary.
            and latest_attempt.failure_reason == "bundle rejected: execution profile is not allowlisted"
            and all(
                (
                    attempt.failure_reason == "bundle rejected: execution profile is not allowlisted"
                    or str(attempt.failure_reason or "").startswith("dispatcher submit failed:")
                )
                for attempt in unit.attempts
            )
        )
        prelaunch_deployment_failure = bool(
            latest_attempt is not None
            # Recovery can refresh an Origin bundle only when this WorkUnit
            # has never crossed the remote-run boundary. Checking merely the
            # latest attempt could mask an earlier staged execution and
            # duplicate scientific work.
            and not any(attempt.external_run_id is not None for attempt in unit.attempts)
            and latest_attempt.failure_reason
            and latest_attempt.failure_reason.startswith(
                "dispatcher submit failed: origin handoff does not support profile"
            )
        )
        recoverable_prelaunch_terminal = self._recoverable_prelaunch_terminal(
            unit,
            prelaunch_deployment_failure=prelaunch_deployment_failure,
            prelaunch_remote_allowlist_failure=prelaunch_remote_allowlist_failure,
        )
        recoverable_storage_terminal = self._recoverable_storage_terminal(unit, job_id)
        if (
            unit.status != WorkUnitStatus.FAILED_RETRIABLE
            and not recoverable_prelaunch_terminal
            and not recoverable_storage_terminal
        ):
            raise ValueError(f"work unit is not retryable from status {unit.status.value}")
        if recoverable_storage_terminal:
            previous_class = latest_attempt.failure_class
            latest_attempt.failure_class = (
                FailureClass.RESOURCE_EXHAUSTION
                if is_storage_exhaustion_failure(latest_attempt.failure_reason or "")
                else FailureClass.INFRASTRUCTURE
            )
            # Preserve the original failure text and Attempt identity. This
            # explicit retry corrects only the proven legacy classification.
            self._event(
                "work_unit.failure_reclassified", actor_id, "work_unit", work_unit_id,
                job_id=job_id, attempt_id=latest_attempt.attempt_id,
                previous_failure_class=previous_class.value if previous_class else None,
                failure_class=latest_attempt.failure_class.value,
                reason_code="confirmed_remote_storage_failure_explicit_retry",
            )
        if recoverable_prelaunch_terminal:
            # A bundle that never reached a worker did not consume a compute
            # attempt.  Preserve the failed launch records and grant one
            # explicit recovery attempt instead of forcing a new Job.
            unit.max_attempts += 1
        if unit.attempt_count >= unit.max_attempts:
            unit.status = WorkUnitStatus.FAILED_TERMINAL
            job.status = JobStatus.FAILED_TERMINAL
            self.repository.put_job(job)
            raise ValueError("work unit has exhausted its retry limit")
        unit.status = WorkUnitStatus.QUEUED
        unit.assigned_machine_id = None
        unit.actual_duration_s = None
        unit.progress_percent = 0.0
        unit.dispatch_not_before_at = None
        unit.dispatch_failure_count = 0
        unit.failure_reason = None
        # A unit retry must not hide other active work in the same Job.  The
        # dispatcher considers both QUEUED and RUNNING jobs, so preserve
        # RUNNING while another unit still owns a compute slot.
        if any(
            candidate.status in {
                WorkUnitStatus.ASSIGNED,
                WorkUnitStatus.RUNNING,
                WorkUnitStatus.RECONCILE_PENDING,
                WorkUnitStatus.COLLECTING,
            }
            for candidate in job.work_units
        ):
            job.status = JobStatus.RUNNING
        else:
            job.status = JobStatus.QUEUED
        self.repository.put_job(job)
        self._event("work_unit.retried", actor_id, "work_unit", work_unit_id, job_id=job_id)
        return job

    _REASSIGN_ACTIVE_ATTEMPT_STATES = {
        "assigned",
        "submitting",
        "running",
        "cancel_pending",
        "reconcile_pending",
        "uncertain",
        "collecting",
    }

    @fenced_reassignment
    def reassign_unit(
        self,
        job_id: str,
        work_unit_id: str,
        target_machine_id: str,
        *,
        actor_id: str,
        reason: str = "",
    ) -> dict:
        """Redirect one unit to another machine via cancel → pin → retry.

        This is deliberately a bounded *step* primitive, not one atomic
        operation. A mid-flight unit first only receives a cancellation
        request (its attempt enters ``cancel_pending``); the caller re-invokes
        once the cancellation has fully propagated. The retry reuses the
        existing work_unit_id, so the no-recompute guarantees (idempotent run
        directories, hash-validated finalization) apply unchanged and no
        duplicate scientific work can be created.
        """
        job = self.repository.get_job(job_id)
        if job is None:
            raise KeyError(f"job not found: {job_id}")
        unit = next((item for item in job.work_units if item.work_unit_id == work_unit_id), None)
        if unit is None:
            raise KeyError(f"work unit not found: {work_unit_id}")
        reason = reason.strip()
        if not reason:
            raise ValueError("改派必须填写可审计原因")
        if job.status in {JobStatus.COMPLETED, JobStatus.FAILED_TERMINAL}:
            raise ValueError(f"job 已处于终态 {job.status.value}，无法改派单元")
        if (
            job.status == JobStatus.CANCELLED
            and unit.status != WorkUnitStatus.CANCELLED
        ):
            # Cancelling the last in-flight unit flips the job to CANCELLED
            # before step two runs. Reviving exactly that cancelled unit is
            # the sanctioned continuation; anything else inside an
            # intentionally cancelled job stays rejected.
            raise ValueError("job 已被取消；改派仅允许针对其中已取消等待传播完成的单元")
        if unit.status in {
            WorkUnitStatus.COLLECTING,
            WorkUnitStatus.COMPLETED,
            WorkUnitStatus.FAILED_TERMINAL,
        }:
            raise ValueError(f"unit 当前状态 {unit.status.value} 不允许改派")
        target_machine_id = str(target_machine_id or "").strip()
        if not target_machine_id:
            raise ValueError("必须提供目标机器 ID")
        target_machine = self.repository.get_machine(target_machine_id)
        if target_machine is None:
            raise ValueError(f"目标机器不存在: {target_machine_id}")
        target_policy = self.repository.get_policy(target_machine_id)
        if target_policy is not None and target_policy.owner_mode == MachineMode.EMERGENCY_STOP:
            raise ValueError(f"目标机器 {target_machine_id} 处于紧急停止模式，无法接收改派")
        if unit.assigned_machine_id and unit.assigned_machine_id == target_machine_id:
            raise ValueError("unit 已分配在目标机器上，无需改派")
        if unit.attempt_count >= unit.max_attempts:
            # Pre-check: retry_unit would otherwise mark the unit terminal as
            # a side effect while raising, which must not happen for a mere
            # placement change request.
            raise ValueError("unit 已耗尽全部重试次数，无法改派")
        previous_machine_id = unit.assigned_machine_id
        latest_attempt = unit.attempts[-1] if unit.attempts else None
        unit_in_flight = (
            unit.status in {
                WorkUnitStatus.ASSIGNED,
                WorkUnitStatus.RUNNING,
                WorkUnitStatus.RECONCILE_PENDING,
            }
            or any(
                attempt.state in self._REASSIGN_ACTIVE_ATTEMPT_STATES
                for attempt in unit.attempts
            )
        )
        if unit_in_flight:
            if latest_attempt is not None and latest_attempt.state == "cancel_pending":
                raise ValueError("unit 的取消仍在向执行器传播，请稍后再次发起改派")
            self.cancel_unit(
                job_id,
                work_unit_id,
                actor_id=actor_id,
                reason=f"reassign to {target_machine_id}: {reason}",
            )
            return {
                "stage": "cancel_requested",
                "job": self.repository.get_job(job_id),
            }
        self._pin_unit_machine(job_id, work_unit_id, target_machine_id, actor_id=actor_id)
        if unit.status == WorkUnitStatus.QUEUED:
            result = self.repository.get_job(job_id)
            stage = "reassigned"
        else:
            result = self.retry_unit(
                job_id,
                work_unit_id,
                actor_id=actor_id,
                allow_cancelled=True,
            )
            stage = "reassigned"
        self._event(
            "work_unit.reassigned",
            actor_id,
            "work_unit",
            work_unit_id,
            job_id=job_id,
            target_machine_id=target_machine_id,
            previous_machine_id=previous_machine_id,
            reason=reason,
            stage=stage,
        )
        return {"stage": stage, "job": result}

    def _pin_unit_machine(
        self,
        job_id: str,
        work_unit_id: str,
        target_machine_id: str,
        *,
        actor_id: str,
    ) -> None:
        """Persist the unit-level placement pin consumed by the dispatcher."""

        def apply_pin(job: JobEnvelope) -> None:
            unit = next(
                (item for item in job.work_units if item.work_unit_id == work_unit_id),
                None,
            )
            if unit is None:
                raise KeyError(f"work unit not found: {work_unit_id}")
            # The model validator requires required and preferred to agree
            # when both are set; pinning both keeps the placement contract
            # consistent while the unit-level pin overrides job placement.
            unit.required_machine_id = target_machine_id
            unit.preferred_machine_id = target_machine_id

        self.repository.mutate_job(job_id, apply_pin, hydrate_blobs=False)

    def migrate_unstarted_solver_contract(
        self,
        job_id: str,
        *,
        approval_id: str,
        actor_id: str,
        solver_variants: set[SolverVariant] | None = None,
        reason: str = "migrate unstarted units to the approved MUMPS/cuDSS contract",
        expected_revision: int | None = None,
    ) -> JobEnvelope:
        """Set an approved execution envelope without replacing scientific inputs.

        Omitting variants retains the historical mixed-solver CLI operation.
        Explicit controls also require complete structured scientific evidence.
        """
        from .repository import RevisionConflictError

        reason = reason.strip()
        if not reason or len(reason) > 1000:
            raise ValueError("unstarted solver changes require an explicit reason")
        if expected_revision is not None and (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise ValueError("expected Job revision must be a nonnegative integer")
        requested = (
            {SolverVariant.MUMPS, SolverVariant.CUDSS}
            if solver_variants is None
            else {SolverVariant(value) for value in solver_variants}
        )
        if not requested:
            raise ValueError("at least one approved solver variant is required")
        changed: list[str] = []
        previous_revision = 0
        approval: SolverCompatibilityApproval | None = None

        def apply(job: JobEnvelope) -> None:
            nonlocal approval, previous_revision
            changed.clear()
            if expected_revision is not None and job.revision != expected_revision:
                raise RevisionConflictError(
                    f"stale job revision for {job_id}: expected {expected_revision}, got {job.revision}"
                )
            previous_revision = job.revision
            approval = self.repository.get_solver_approval(approval_id)
            if approval is None or not approval.is_active():
                raise ValueError("active solver approval not found")
            if (
                approval.project_id != job.project_id
                or approval.execution_profile_id != job.execution_profile_id
                or approval.template_sha256 != job.template_sha256
                or approval.template_role != job.template_role
                or (
                    job.study_kind is not None
                    and job.study_kind not in approval.allowed_study_kinds
                )
                or (job.study_kind is None and bool(approval.allowed_study_kinds))
            ):
                raise ValueError("solver approval does not match the Job scientific contract")
            if not requested.issubset(approval.solver_variants):
                raise ValueError("requested solvers are outside the approved solver contract")
            profile = self.repository.get_profile(job.execution_profile_id)
            comsol_versions = {
                capability.removeprefix("comsol-")
                for capability in (profile.required_capabilities if profile else set())
                if capability.startswith("comsol-")
            }
            if profile is None or (comsol_versions and approval.comsol_version not in comsol_versions):
                raise ValueError("solver approval COMSOL version does not match the execution Profile")
            if (
                job.execution_profile_id in SEALED_COMSOL_PROFILE_IDS
                and not self.runtime_policy.accepts_new_approval(approval.runtime_version)
            ):
                raise ValueError("solver approval does not use an accepted sealed runtime")
            payloads = self._job_item_payloads(job)
            if solver_variants is not None or expected_revision is not None or payloads:
                self._validate_solver_approval_evidence(
                    approval, job.execution_profile_id, payloads,
                )
            eligible = [
                unit for unit in job.work_units
                if unit.status in {WorkUnitStatus.QUEUED, WorkUnitStatus.FAILED_RETRIABLE}
                and not any(
                    attempt.execution_started or attempt.execution_completed
                    or attempt.state not in {"failed", "cancelled"}
                    for attempt in unit.attempts
                )
            ]
            if not eligible:
                raise ValueError("job has no unstarted units eligible for solver migration")
            eligible_ids = {unit.work_unit_id for unit in eligible}
            if any(
                reservation.work_unit_id in eligible_ids
                for reservation in self.repository.list_dispatch_reservations(
                    job_id=job_id, active_only=True,
                )
            ):
                raise ValueError(
                    "unstarted solver change requires retiring active standby reservations first"
                )
            for unit in eligible:
                unit.allowed_solver_variants = set(requested)
                unit.solver_policy = SolverPolicy.AUTO_FAST
                unit.resource_mode = ResourceMode.DYNAMIC
                unit.solver_policy_explicit = True
                unit.solver_approval_id = approval.approval_id
                # GPU requirements belong to the mutable execution envelope;
                # historical Attempt allocations and scientific items stay frozen.
                gpus = 0 if requested == {SolverVariant.MUMPS} else max(1, unit.resources.gpus)
                unit.resources = unit.resources.model_copy(update={"gpus": gpus})
                if unit.resolved_resources is not None:
                    unit.resolved_resources = unit.resolved_resources.model_copy(update={
                        "resources": unit.resolved_resources.resources.model_copy(update={"gpus": gpus}),
                    })
                changed.append(unit.work_unit_id)
            job.solver_policy = SolverPolicy.AUTO_FAST
            job.resource_mode = ResourceMode.DYNAMIC
            job.solver_policy_explicit = True
            job.solver_approval_id = approval.approval_id
            job.solver_compatibility_fingerprint = approval.fingerprint

        # Hydrate for approval/FEM validation. The repository's aggregate CAS
        # prevents a concurrent Dispatcher Attempt from being overwritten.
        # An explicit revision is never silently retried against another state.
        job = self.repository.mutate_job(
            job_id, apply, retries=1 if expected_revision is not None else 8,
            hydrate_blobs=True,
        )
        assert approval is not None
        self._event(
            "job.unstarted_solver_contract_migrated",
            actor_id,
            "job",
            job.job_id,
            approval_id=approval.approval_id,
            runtime_version=approval.runtime_version,
            solver_variants=sorted(variant.value for variant in requested),
            reason=reason,
            previous_revision=previous_revision,
            revision=job.revision,
            changed_unit_ids=changed,
            changed_unit_count=len(changed),
            preserved_unit_count=len(job.work_units) - len(changed),
        )
        return job

    def _upshift_resource_policy_after_failure(
        self,
        job: JobEnvelope,
        work_unit_id: str,
        *,
        error: str,
        actor_id: str,
    ) -> None:
        settings = self.repository.get_feature_settings()
        policy = settings.resource_policies.get(job.execution_profile_id)
        if policy is None:
            return
        unit = next(item for item in job.work_units if item.work_unit_id == work_unit_id)
        attempt = self._current_attempt(unit)
        frozen = (
            attempt.resolved_resources.resources
            if attempt is not None and attempt.resolved_resources is not None
            else unit.resources
        )
        message = error.lower()
        memory_failure = any(
            marker in message for marker in ("out of memory", "not enough memory", "memory limit")
        )
        disk_failure = any(
            marker in message for marker in ("no space left", "disk full", "disk quota")
        )
        updates: dict[str, int] = {}
        if memory_failure:
            observed = max(
                frozen.memory_mb,
                attempt.peak_memory_mb or 0 if attempt is not None else 0,
            )
            updates["memory_mb"] = min(
                policy.maximum.memory_mb,
                max(
                    policy.baseline.memory_mb,
                    observed + max(math.ceil(observed * 0.25), policy.memory_margin_floor_mb),
                ),
            )
        if disk_failure:
            observed = max(
                frozen.disk_mb,
                attempt.peak_disk_mb or 0 if attempt is not None else 0,
            )
            updates["disk_mb"] = min(
                policy.maximum.disk_mb,
                max(
                    policy.baseline.disk_mb,
                    observed + max(math.ceil(observed * 0.25), policy.disk_margin_floor_mb),
                ),
            )
        if not updates:
            return
        baseline = policy.baseline.model_copy(update=updates)
        if baseline == policy.baseline:
            return
        updated = policy.model_copy(
            deep=True,
            update={"baseline": baseline, "revision": policy.revision + 1},
        )
        settings.resource_policies[job.execution_profile_id] = updated
        settings.updated_at = datetime.now(timezone.utc)
        self.repository.put_feature_settings(settings)
        self._event(
            "resource_policy.upshifted",
            actor_id,
            "execution_profile",
            job.execution_profile_id,
            revision=updated.revision,
            work_unit_id=work_unit_id,
            baseline=baseline.model_dump(mode="json"),
            reason=error,
        )

    @staticmethod
    def _recoverable_prelaunch_terminal(
        unit: WorkUnit,
        *,
        prelaunch_deployment_failure: bool | None = None,
        prelaunch_remote_allowlist_failure: bool | None = None,
    ) -> bool:
        """Identify terminal failures that never crossed the worker boundary."""
        latest = unit.attempts[-1] if unit.attempts else None
        if latest is None or unit.status != WorkUnitStatus.FAILED_TERMINAL or unit.max_attempts >= 10:
            return False
        if (
            latest.failure_class != FailureClass.INFRASTRUCTURE
            and not str(latest.failure_reason or "").startswith(
                "dispatcher submit failed: origin handoff does not support profile"
            )
        ):
            return False
        # Once a worker has acknowledged a running Study, retrying would
        # duplicate scientific execution. Only prelaunch failures are safe.
        if latest.execution_started or latest.execution_completed:
            return False
        if prelaunch_remote_allowlist_failure is None:
            prelaunch_remote_allowlist_failure = (
                latest.failure_reason == "bundle rejected: execution profile is not allowlisted"
                and all(
                    attempt.failure_reason == "bundle rejected: execution profile is not allowlisted"
                    or str(attempt.failure_reason or "").startswith("dispatcher submit failed:")
                    for attempt in unit.attempts
                )
            )
        if prelaunch_deployment_failure is None:
            prelaunch_deployment_failure = bool(
                latest.failure_reason
                and latest.failure_reason.startswith(
                    "dispatcher submit failed: origin handoff does not support profile"
                )
                and not any(attempt.external_run_id is not None for attempt in unit.attempts)
            )
        if prelaunch_remote_allowlist_failure:
            return True
        if prelaunch_deployment_failure:
            return True
        if latest.failure_reason and latest.failure_reason.startswith("prelaunch_failure:"):
            return True
        return bool(
            latest.failure_class == FailureClass.INFRASTRUCTURE
            and not any(
                attempt.external_run_id is not None for attempt in unit.attempts
            )
        )

    def stop_simulated_units(self, machine_id: str, *, actor_id: str) -> int:
        stopped = 0
        for job in self.repository.list_operational_jobs():
            for unit in job.work_units:
                if (
                    unit.assigned_machine_id == machine_id
                    and unit.status in {WorkUnitStatus.ASSIGNED, WorkUnitStatus.RUNNING}
                ):
                    self.fail_unit(
                        job.job_id,
                        unit.work_unit_id,
                        error="simulated emergency stop",
                        retryable=False,
                        actor_id=actor_id,
                    )
                    stopped += 1
        return stopped

    def register_member_runtime_successors(self, *, actor_id: str) -> list[str]:
        """Register only the explicitly selected, independently compared release.

        This extends the original approval to owner-session scheduling code;
        it neither changes science nor creates new scientific acceptance claims.
        The predecessor stays authoritative for revocation and project scope.
        """
        if (not self.member_release.owner_session_required
                or self.member_release.base_runtime_version == self.member_release.runtime_version):
            return []
        from .member_release_catalog import approved_scientific_equivalence
        evidence = approved_scientific_equivalence(self.member_release)
        registered = []
        for predecessor in self.repository.list_solver_approvals(active_only=True):
            candidate = self._register_member_runtime_successor(predecessor, actor_id=actor_id, evidence=evidence)
            if candidate is not None:
                registered.append(candidate.approval_id)
        return registered

    def _register_member_runtime_successor(self, predecessor, *, actor_id: str, evidence=None):
        if (not self.member_release.owner_session_required
                or self.member_release.base_runtime_version == self.member_release.runtime_version
                or not predecessor.is_active()
                or predecessor.runtime_version != self.member_release.base_runtime_version
                or predecessor.runtime_predecessor_approval_id is not None):
            return None
        grant = self.repository.get_project_grant(predecessor.project_id)
        profile = self.repository.get_profile(predecessor.execution_profile_id)
        if (grant is None or predecessor.execution_profile_id not in grant.allowed_profiles
                or profile is None or not profile.executor_kind.startswith("workbench_comsol")):
            return None
        from .member_release_catalog import approved_scientific_equivalence
        evidence = evidence or approved_scientific_equivalence(self.member_release)
        evidence_hash = sha256_value(evidence)
        candidate_id = "solver-member-" + sha256_value({"predecessor_approval_id": predecessor.approval_id,
            "predecessor_fingerprint": predecessor.fingerprint, "runtime_equivalence_sha256": evidence_hash})[:32]
        existing = self.repository.get_solver_approval(candidate_id)
        if existing is not None:
            # Explicit revocation/expiry of a successor is not reset on restart.
            from .runtime_compatibility import same_scientific_environment
            if (not same_scientific_environment(predecessor, existing)
                    or existing.runtime_version != self.member_release.runtime_version
                    or existing.runtime_predecessor_approval_id != predecessor.approval_id
                    or existing.runtime_equivalence_sha256 != evidence_hash):
                raise ValueError("member runtime successor receipt differs from its approved science")
            return existing
        values = predecessor.model_dump(mode="json")
        values.update(approval_id=candidate_id, runtime_version=self.member_release.runtime_version,
            runtime_predecessor_approval_id=predecessor.approval_id, runtime_equivalence_sha256=evidence_hash,
            fingerprint="", approved_by=actor_id, created_at=datetime.now(timezone.utc))
        candidate = SolverCompatibilityApproval.model_validate(values)
        self.approve_solver(candidate, actor_id=actor_id)
        self._event("member_release.runtime_equivalence_registered", actor_id, "solver_approval", candidate_id,
            project_id=predecessor.project_id, execution_profile_id=predecessor.execution_profile_id,
            predecessor_approval_id=predecessor.approval_id, runtime_version=candidate.runtime_version,
            equivalence_sha256=evidence_hash, scientific_capsule_sha256=evidence["scientific_capsule_sha256"],
            scientific_contract_inherited=True)
        return candidate

    def request_member_retirement(self, machine_id: str, operation_id: str, *, actor_id: str,
                                  reason: str = "member_client_uninstall", is_admin: bool = False) -> dict:
        """Durably stop new assignments before the owner requests local drain."""
        from .submission_operations import operation_id as checked_operation_id
        operation_id = checked_operation_id(operation_id)
        if reason != "member_client_uninstall":
            raise ValueError("member retirement reason must be member_client_uninstall")

        def accept(repository):
            scope = copy.copy(self)
            scope.repository = repository
            machine = repository.get_machine(machine_id)
            policy = repository.get_policy(machine_id)
            config = repository.get_machine_execution_config(machine_id)
            if machine is None or policy is None or config is None or not config.root_uuid:
                raise KeyError("member execution identity not found")
            if machine.owner_user_id != actor_id and not is_admin:
                raise PermissionError("member retirement requires machine owner")
            old = repository.get_member_retirement(machine_id)
            if old is not None:
                if old["operation_id"] != operation_id or old["request_sha256"] != sha256_value({
                    "operation_id": operation_id, "actor_id": actor_id, "reason": reason}):
                    raise ValueError("different member retirement already exists")
                return scope.member_retirement_status(machine_id, operation_id)
            now = datetime.now(timezone.utc).isoformat()
            receipt = {"schema_version": 1, "operation_id": operation_id, "machine_id": machine_id,
                "actor_id": actor_id, "machine_owner_id": machine.owner_user_id,
                "root_uuid": config.root_uuid, "runtime_version": config.runtime_version,
                "remote_root_sha256": sha256_value(config.remote_root), "reason": reason,
                "request_sha256": sha256_value({"operation_id": operation_id, "actor_id": actor_id, "reason": reason}),
                "created_at": now, "withdrawn": [], "last_progress_at": None,
                "last_progress_sha256": None, "remote_active_run_ids": [], "remote_pending_run_ids": [],
                "identity_and_results_preserved": True, "personal_token_revoked": False,
                "project_authorization_revoked": False, "machine_authorization_revoked": False}
            repository.put_member_retirement(receipt)
            policy.owner_mode = MachineMode.PAUSED
            repository.put_policy(policy)
            config.enabled = False
            repository.put_machine_execution_config(config)
            scope._event("member_retirement.requested", actor_id, "machine", machine_id,
                operation_id=operation_id, root_uuid=config.root_uuid, runtime_version=config.runtime_version,
                identity_and_results_preserved=True)
            return scope.member_retirement_status(machine_id, operation_id)

        return self.repository.submission_transaction(accept)

    def member_retirement_status(self, machine_id: str, operation_id: str) -> dict:
        from .submission_operations import operation_id as checked_operation_id
        operation_id = checked_operation_id(operation_id)
        receipt = self.repository.get_member_retirement(machine_id)
        if receipt is None or receipt["operation_id"] != operation_id:
            raise KeyError("member retirement operation not found")
        machine = self.repository.get_machine(machine_id)
        config = self.repository.get_machine_execution_config(machine_id)
        if (machine is None or config is None or machine.owner_user_id != receipt["machine_owner_id"]
                or config.root_uuid != receipt["root_uuid"] or config.runtime_version != receipt["runtime_version"]
                or sha256_value(config.remote_root) != receipt["remote_root_sha256"] or config.enabled):
            raise ValueError("member retirement execution identity changed")
        queued, inflight, uncertain = [], [], []
        for job in self.repository.list_member_retirement_jobs(machine_id):
            for unit in job.work_units:
                active = [attempt for attempt in unit.attempts if attempt.machine_id == machine_id
                          and attempt.state not in {"completed", "failed", "cancelled"}]
                if unit.assigned_machine_id == machine_id and not active and unit.status in {
                    WorkUnitStatus.ASSIGNED, WorkUnitStatus.RUNNING, WorkUnitStatus.RECONCILE_PENDING, WorkUnitStatus.COLLECTING}:
                    uncertain.append({"job_id": job.job_id, "work_unit_id": unit.work_unit_id,
                        "attempt_id": None, "reason_code": "assigned_unit_missing_active_attempt"})
                for attempt in active:
                    item = {"job_id": job.job_id, "work_unit_id": unit.work_unit_id,
                        "attempt_id": attempt.attempt_id, "external_run_id": attempt.external_run_id,
                        "state": attempt.state}
                    if attempt.state in {"uncertain", "reconcile_pending", "submitting", "cancel_pending"}:
                        uncertain.append(item)
                    elif attempt.execution_started or attempt.started_at is not None or attempt.state in {"running", "collecting"}:
                        inflight.append(item)
                    else:
                        queued.append(item)
        reservations = [{"reservation_id": item.reservation_id, "state": item.state,
                         "external_run_id": item.external_run_id} for item in self.repository.list_dispatch_reservations(
                             machine_id=machine_id, active_only=True)]
        pending = {"queued": queued, "inflight": inflight, "uncertain": uncertain, "reservations": reservations}
        confirmed = receipt["last_progress_at"] is not None
        ready = (confirmed and not any(pending.values()) and not receipt["remote_active_run_ids"]
                 and not receipt["remote_pending_run_ids"])
        return {**receipt, "state": "ready_to_uninstall" if ready else "draining", "pending": pending,
                "remote_confirmation_required": not confirmed}

    def reconcile_member_retirement(self, machine_id: str, operation_id: str, progress: dict, *, actor_id: str) -> dict:
        """Consume fixed, authenticated supervisor no-start evidence atomically."""
        current = self.member_retirement_status(machine_id, operation_id)
        if (not isinstance(progress, dict) or type(progress.get("schema_version")) is not int
                or progress["schema_version"] != 1 or any(progress.get(key) != current[key]
                for key in ("operation_id", "machine_id", "root_uuid", "runtime_version"))):
            raise ValueError("member retirement progress identity mismatch")
        try:
            observed = datetime.fromisoformat(str(progress["updated_at"]).replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - observed).total_seconds()
            if observed.tzinfo is None or not -15 <= age <= 120:
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise ValueError("member retirement progress is stale or invalid") from None
        for field in ("withdrawals", "active_run_ids", "pending_run_ids"):
            if not isinstance(progress.get(field), list) or len(progress[field]) > 10000:
                raise ValueError("member retirement progress exceeds bound")
        if any(not isinstance(item, str) for key in ("active_run_ids", "pending_run_ids") for item in progress[key]):
            raise ValueError("member retirement progress run identities invalid")
        for proof in progress["withdrawals"]:
            if (not isinstance(proof, dict) or proof.get("state") != "cancelled"
                    or proof.get("never_started") is not True or proof.get("artifacts_available") is not False
                    or proof.get("started_at") is not None or any(
                        not isinstance(proof.get(key), str) or not 0 < len(proof[key]) <= 512
                        for key in ("external_run_id", "job_id", "work_unit_id", "request_hash"))
                    or len(proof["request_hash"]) != 64
                    or any(char not in "0123456789abcdef" for char in proof["request_hash"])):
                raise ValueError("member retirement lacks exact never-started proof")
            if proof.get("external_run_id") in progress["active_run_ids"] + progress["pending_run_ids"]:
                raise ValueError("member retirement withdrawal contradicts active run evidence")
        if len({proof["external_run_id"] for proof in progress["withdrawals"]}) != len(progress["withdrawals"]):
            raise ValueError("member retirement withdrawal identities are ambiguous")

        def apply(repository):
            scope = copy.copy(self)
            scope.repository = repository
            receipt = scope.member_retirement_status(machine_id, operation_id)
            withdrawn = list(receipt["withdrawn"])
            known = {item["external_run_id"] for item in withdrawn}
            reservations = repository.list_dispatch_reservations(machine_id=machine_id, active_only=True)
            for proof in progress["withdrawals"]:
                job = repository.get_operational_job(proof.get("job_id", ""))
                unit = next((item for item in job.work_units if item.work_unit_id == proof.get("work_unit_id")), None) if job else None
                attempt = next((item for item in unit.attempts if item.machine_id == machine_id
                    and item.external_run_id == proof.get("external_run_id")), None) if unit else None
                if unit is None or proof.get("external_run_id") in known:
                    continue
                remote = repository.get_remote_run(proof.get("external_run_id", ""))
                reservation = next((item for item in reservations if item.external_run_id == proof.get("external_run_id")
                    and item.job_id == job.job_id and item.work_unit_id == unit.work_unit_id), None)
                reference_hash = remote.request_hash if remote else (reservation.request_hash if reservation else None)
                if (not reference_hash or proof.get("request_hash") != reference_hash
                        or (remote and (remote.machine_id != machine_id or remote.job_id != job.job_id
                                         or remote.work_unit_id != unit.work_unit_id or remote.artifacts_available
                                         or remote.state not in {RemoteRunState.STAGED, RemoteRunState.PREPARED,
                                                                 RemoteRunState.QUEUED, RemoteRunState.CANCELLED}))):
                    continue  # Lost delivery identity needs ordinary reconciliation.
                if attempt is None:
                    if (reservation is None or unit.status != WorkUnitStatus.QUEUED or any(
                            item.state not in {"cancelled", "failed", "completed"} for item in unit.attempts)):
                        continue
                elif (attempt.execution_started or attempt.execution_completed or attempt.started_at is not None
                        or attempt.state not in {"assigned", "submitting", "uncertain", "reconcile_pending"}
                        or unit.assigned_machine_id != machine_id or unit.attempts[-1].attempt_id != attempt.attempt_id
                        or unit.status not in {WorkUnitStatus.ASSIGNED, WorkUnitStatus.RECONCILE_PENDING}):
                    continue
                if attempt is not None:
                    attempt.state = "cancelled"
                    attempt.finished_at = observed
                    attempt.failure_reason = "member owner retirement: exact remote never-started withdrawal"
                    unit.status = WorkUnitStatus.QUEUED
                    unit.assigned_machine_id = None
                    unit.failure_reason = None
                    unit.progress_percent = 0
                    unit.eta_s = None
                    # Keep original Attempt identity and scientific envelope;
                    # voluntary no-start withdrawal preserves retry budget.
                    unit.attempt_count = max(0, unit.attempt_count - 1)
                    job.status = derived_job_status(job)
                    repository._put_job_operational(job)
                if reservation is not None:
                    scope.finish_dispatch_reservation(reservation.reservation_id, state="cancelled", actor_id=actor_id,
                        reason="member owner retirement: exact remote never-started withdrawal")
                if remote is not None:
                    remote.state = RemoteRunState.CANCELLED
                    remote.message = "cancelled before launch: member owner retirement"
                    repository.put_remote_run(remote)
                entry = {key: proof[key] for key in ("external_run_id", "job_id", "work_unit_id", "request_hash")}
                entry.update(attempt_id=attempt.attempt_id if attempt else None,
                    reservation_id=reservation.reservation_id if reservation else None, evidence_sha256=sha256_value(proof))
                withdrawn.append(entry)
                known.add(entry["external_run_id"])
                scope._event("member_retirement.queued_attempt_withdrawn", actor_id,
                    "attempt" if attempt else "dispatch_reservation", attempt.attempt_id if attempt else reservation.reservation_id,
                    operation_id=operation_id, machine_id=machine_id, retry_budget_preserved=True, **entry)
            saved = repository.get_member_retirement(machine_id)
            saved.update(withdrawn=withdrawn, last_progress_at=progress["updated_at"],
                last_progress_sha256=sha256_value(progress), remote_active_run_ids=progress["active_run_ids"],
                remote_pending_run_ids=progress["pending_run_ids"])
            repository.put_member_retirement(saved)
            return scope.member_retirement_status(machine_id, operation_id)

        return self.repository.submission_transaction(apply)
