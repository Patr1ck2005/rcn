"""Conditionally admit a member only from center-owned acceptance evidence.

Public methods accept consent, never a passed checklist. The finalizer reads the
existing acceptance, machine/configuration and independent observation records.
It performs one metadata transaction; it never sends remote commands or restarts
science. Scope expiry/revocation affects future placement, not running Attempts.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

from pydantic import Field, field_validator
from sqlalchemy import select

from .member_admission_contract import ConditionalAdmissionRequest, MemberExecutionLimit, canonical_digest
from .admission_governance import (TRUST_FIRST, offer_governance, consent_policy_digest,
    trust_readiness_blockers)
from .member_admission_invitation import checked_offer, validate_offer_scope
from .member_enrollment import EnrollmentUnavailable, StrictModel
from .member_relay import _root_claim
from .member_transport import MemberTransportService
from .member_worker_root_contract import MemberWorkerRoots, WorkerRootRequest, manifest_hash
from .models import (AcceptanceStatus, ApprovalRecord, ApprovalScope, EnrollmentRecord,
    MachineExecutionConfig, MachineMode, MachinePolicy, MachineState, RemoteRunState,
    SshAcceptanceRun, TimeWindow, UserRole)
from .repository import (ApprovalRow, EnrollmentRow, MachineExecutionConfigRow,
    MachineOperationalStatusRow, MachineRow, PolicyRow, RemoteRunRow, SshAcceptanceRow)

OFFER_PATH = '/v1/member-enrollment/compute-offer'
CONSENT_PATH = '/v1/member-enrollment/compute-consent'
STATUS_PATH = '/v1/member-enrollment/admission-status'


class ComputePreferences(StrictModel):
    max_cpus: int = Field(strict=True, ge=1, le=256)
    max_memory_mb: int = Field(strict=True, ge=256, le=1048576)
    memory_reserve_mb: int = Field(strict=True, ge=0, le=1048576)
    timezone: str = 'Asia/Shanghai'
    weekly_windows: dict[int, list[TimeWindow]]
    keyboard_idle_min_s: int = Field(strict=True, ge=0, le=86400, default=1200)

    @field_validator('timezone')
    @classmethod
    def timezone_exists(cls, value):
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        try:
            ZoneInfo(value)
        except (ValueError, ZoneInfoNotFoundError):
            raise ValueError('known_timezone_required') from None
        return value

    @field_validator('weekly_windows')
    @classmethod
    def bounded_windows(cls, value):
        if not value or any(day not in range(7) for day in value) or not any(value.values()) or sum(len(v) for v in value.values()) > 28:
            raise ValueError('bounded_nonempty_weekly_schedule_required')
        return value


class ComputeConsentRequest(WorkerRootRequest):
    offer_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    accept_compute: bool = Field(strict=True)
    preferences: ComputePreferences


def admission_statement(purpose: str, descriptor: dict, *, offer_sha256=None, preferences=None) -> bytes:
    if purpose not in {'offer', 'consent', 'status'}:
        raise ValueError('fixed admission operation required')
    value = {'purpose': 'rcn-member-compute-'+purpose+'-v1', 'root_manifest': descriptor}
    if purpose == 'consent':
        value.update(offer_sha256=offer_sha256, accept_compute=True, preferences=preferences)
    import json
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)+'\n').encode('ascii')


def _dump(value):
    return value.model_dump(mode='json')


def acceptance_execution_config_digest(config) -> str:
    payload=_dump(config)
    payload['execution_provenance']={k:v for k,v in payload.get('execution_provenance',{}).items()
        if not k.startswith('scientific_audit_')}
    for key in ('enabled','operational_execution','conditional_production','startup_after_reboot',
                'numeric_equivalence','capability_warnings','updated_at'):
        payload.pop(key,None)
    return canonical_digest(payload)


def _stored_consent(record):
    consent = record.member_compute_consent
    try:
        if not isinstance(consent, dict) or set(consent) != {'body', 'consent_sha256', 'policy_sha256', 'recorded_at'}:
            raise ValueError('consent missing')
        if canonical_digest(consent['body']) != consent['consent_sha256']:
            raise ValueError('consent changed')
        return consent
    except (TypeError, KeyError, ValueError):
        raise EnrollmentUnavailable() from None


class MemberAdmissions:
    def __init__(self, repository, *, verification_root: Path):
        self.repository = repository
        self.roots = MemberWorkerRoots(repository, verification_root=verification_root)
        self.transport: MemberTransportService = self.roots.transport

    def _context(self, session, request, *, allow_revoked=False):
        record, descriptor = self.roots._context(session, request)
        if not allow_revoked and record.member_admission_result and record.member_admission_result.get('state') == 'revoked':
            raise EnrollmentUnavailable()
        if canonical_digest(_root_claim(record)) != canonical_digest(descriptor):
            raise EnrollmentUnavailable()
        return record, descriptor

    def offer(self, request: WorkerRootRequest) -> dict:
        with self.repository._session() as session:
            record, descriptor = self._context(session, request)
            offer = checked_offer(record) if record.conditional_admission_offer is not None else None
            if offer is not None:
                validate_offer_scope(session, offer)
        self.transport.verify_possession(request, admission_statement('offer', descriptor))
        # Offer is a view, not a grant. No health or machine policy is changed.
        with self.repository._session() as session:
            record, latest = self._context(session, request)
            current_offer = checked_offer(record) if record.conditional_admission_offer is not None else None
            if latest != descriptor or current_offer != offer:
                raise EnrollmentUnavailable()
        return {'offer': offer, 'requires_owner_consent': offer is not None, 'grants_execution': False}

    def consent(self, request: ComputeConsentRequest) -> dict:
        if request.accept_compute is not True:
            raise EnrollmentUnavailable()
        with self.repository._session() as session:
            record, descriptor = self._context(session, request)
            offer = checked_offer(record)
        if request.offer_sha256 != offer['offer_sha256']:
            raise EnrollmentUnavailable()
        preferences = _dump(request.preferences)
        body = {'enrollment_id': record.enrollment_id, 'machine_id': record.machine_id,
            'root_manifest_sha256': manifest_hash(descriptor), 'offer_sha256': request.offer_sha256,
            'accept_compute': True, 'preferences': preferences}
        digest = canonical_digest(body)
        self.transport.verify_possession(request, admission_statement('consent', descriptor,
            offer_sha256=request.offer_sha256, preferences=preferences))
        def write():
            with self.repository._session() as session, session.begin():
                self.transport.enrollment._lock(session, request.enrollment_id)
                record, latest = self._context(session, request)
                if latest != descriptor or checked_offer(record) != offer:
                    raise EnrollmentUnavailable()
                scope = ConditionalAdmissionRequest.model_validate(offer['scope'])
                validate_offer_scope(session, offer)
                if record.member_compute_consent is not None:
                    saved = _stored_consent(record)
                    if saved['body'] != body or saved['consent_sha256'] != digest:
                        raise EnrollmentUnavailable()
                    return {'consent_recorded': True, 'consent_sha256': digest, 'grants_execution': False}
                policy_row = session.get(PolicyRow, record.machine_id)
                policy = MachinePolicy.model_validate(policy_row.payload)
                machine = MachineState.model_validate(session.get(MachineRow, record.machine_id).payload)
                config_row = session.get(MachineExecutionConfigRow, record.machine_id)
                if (record.member_admission_result is not None or policy.owner_mode != MachineMode.PAUSED
                        or policy.admin_mode_override is not None or policy.member_execution_limit is not None
                        or machine.metrics.running_units != 0 or (config_row is not None and config_row.payload.get('enabled'))):
                    raise EnrollmentUnavailable()
                p = request.preferences
                if (p.max_cpus > min(scope.max_cpus, machine.total_cpus)
                        or p.max_memory_mb > min(scope.max_memory_mb, machine.total_memory_mb)
                        or p.memory_reserve_mb >= machine.total_memory_mb
                        or not p.weekly_windows or not any(p.weekly_windows.values())
                        or sum(len(v) for v in p.weekly_windows.values()) > 28):
                    raise EnrollmentUnavailable()
                updated = _dump(policy)
                updated.update(preferences, max_concurrent_units=1, max_gpus=0,
                    external_comsol_termination_authorized=False, updated_at=datetime.now(timezone.utc).isoformat())
                if offer_governance(offer) == TRUST_FIRST:
                    updated.update(shared_machine=True, cpu_reserve_percent=25)
                updated['member_execution_limit'] = _dump(MemberExecutionLimit(
                    project_profiles=scope.project_profiles, person_profiles=scope.person_profiles, max_cpus=p.max_cpus, max_memory_mb=p.max_memory_mb,
                    project_trust_labels=offer['project_trust_labels'],
                    enrollment_id=record.enrollment_id, runtime_version=offer['runtime_version'],
                    offer_sha256=offer['offer_sha256'], consent_sha256=digest,
                    expires_at=(datetime.fromisoformat(offer['expires_at']) if offer['expires_at'] is not None else None)))
                policy = MachinePolicy.model_validate(updated)
                policy_row.payload = _dump(policy)
                record.member_compute_consent = {'body': body, 'consent_sha256': digest,
                    'policy_sha256': canonical_digest(_dump(policy)), 'recorded_at': datetime.now(timezone.utc).isoformat()}
                session.get(EnrollmentRow, record.enrollment_id).payload = _dump(record)
                self.transport.enrollment._audit(session, 'member.compute_consent_recorded',
                    f'machine-agent:{record.machine_id}', record.enrollment_id,
                    consent_sha256=digest, offer_sha256=offer['offer_sha256'], grants_execution=False)
                return {'consent_recorded': True, 'consent_sha256': digest, 'grants_execution': False}
        try:
            return self.repository._retry_sqlite_write(write)
        except (ValueError, TypeError) as exc:
            if isinstance(exc, EnrollmentUnavailable):
                raise
            raise EnrollmentUnavailable() from None

    def status(self, request: WorkerRootRequest) -> dict:
        with self.repository._session() as session:
            record, descriptor = self._context(session, request, allow_revoked=True)
        self.transport.verify_possession(request, admission_statement('status', descriptor))
        with self.repository._session() as session:
            record, latest = self._context(session, request, allow_revoked=True)
            if latest != descriptor:
                raise EnrollmentUnavailable()
            config_row = session.get(MachineExecutionConfigRow, record.machine_id)
            policy = MachinePolicy.model_validate(session.get(PolicyRow, record.machine_id).payload)
            limit = policy.member_execution_limit
            result = record.member_admission_result
            enabled = bool(result and result.get('state') == 'admitted' and config_row and config_row.payload.get('enabled') is True
                and policy.effective_mode() == MachineMode.OPEN and limit and limit.is_active()
                and limit.runtime_version == config_row.payload.get('runtime_version'))
            trust = bool(record.conditional_admission_offer and offer_governance(record.conditional_admission_offer) == TRUST_FIRST)
            payload = {'enrollment_id': record.enrollment_id, 'machine_id': record.machine_id,
                'state': result['state'] if result else (
                    ('awaiting_machine_readiness' if trust else 'awaiting_machine_acceptance')
                    if record.member_compute_consent else 'awaiting_owner_consent'),
                'consent_recorded': record.member_compute_consent is not None,
                'grants_execution': enabled, 'historical_admission': bool(result and result.get('admitted_at'))}
            if trust:
                payload['audit_state'] = result.get('audit_state', 'pending') if result else 'not_admitted'
            return payload

    def acceptance_context(self, session, record, config) -> dict:
        offer = checked_offer(record)
        consent = _stored_consent(record)
        root = _root_claim(record)
        return {'enrollment_id': record.enrollment_id, 'machine_id': record.machine_id,
            'root_manifest_sha256': manifest_hash(root), 'root_uuid': root['root_uuid'],
            'offer_sha256': offer['offer_sha256'], 'consent_sha256': consent['consent_sha256'],
            'runtime_version': offer['runtime_version'], 'execution_config_sha256': acceptance_execution_config_digest(config),
            'policy_sha256': consent['policy_sha256']}

    def finalize(self, enrollment_id: str, run_id: str | None = None) -> dict:
        """Internal center finalizer. There is deliberately no public checklist route."""
        from .connection_health import fresh
        from .models import MachineOperationalStatus
        from .ssh_acceptance import REQUIRED_CHECK_IDS
        def write():
            with self.repository._session() as session, session.begin():
                self.transport.enrollment._lock(session, enrollment_id)
                row = session.get(EnrollmentRow, enrollment_id)
                if row is None:
                    raise EnrollmentUnavailable()
                record = EnrollmentRecord.model_validate(row.payload)
                offer = checked_offer(record)
                trust_first = offer_governance(offer) == TRUST_FIRST
                owner = self.transport.enrollment._user(session, record.owner_user_id)
                if UserRole.MACHINE_OWNER not in owner.roles:
                    raise EnrollmentUnavailable()
                # Current credential/enrollment authorization is checked without a client secret.
                from .repository import MachineCredentialRow
                token = session.get(MachineCredentialRow, record.exchange_credential_id)
                from .models import MachineAgentCredential
                if (not row.used or record.revoked_at is not None or token is None or not token.active
                        or record.enrollment_id != row.enrollment_id or record.owner_user_id != row.owner_user_id
                        or record.code_hash != row.code_hash or record.machine_id != record.invited_machine_id
                        or token.machine_id != record.machine_id or not MachineAgentCredential.model_validate(token.payload).is_active()
                        or token.payload.get('token_hash') != token.token_hash
                        or token.payload.get('credential_id') != token.credential_id
                        or token.payload.get('machine_id') != record.machine_id):
                    raise EnrollmentUnavailable()
                config_row = session.get(MachineExecutionConfigRow, record.machine_id)
                policy_row = session.get(PolicyRow, record.machine_id)
                if config_row is None or policy_row is None:
                    raise EnrollmentUnavailable()
                config = MachineExecutionConfig.model_validate(config_row.payload)
                policy = MachinePolicy.model_validate(policy_row.payload)
                if record.member_admission_result is not None:
                    prior = record.member_admission_result
                    if prior.get('state') != 'admitted' or (not trust_first and prior.get('run_id') != run_id):
                        raise EnrollmentUnavailable()
                    # Never reopen a machine an owner paused after admission.
                    return {**prior, 'grants_execution': bool(config.enabled and policy.effective_mode() == MachineMode.OPEN
                        and policy.member_execution_limit and policy.member_execution_limit.is_active()
                        and policy.member_execution_limit.runtime_version == config.runtime_version)}
                consent = _stored_consent(record)
                scope = ConditionalAdmissionRequest.model_validate(offer['scope'])
                validate_offer_scope(session, offer)
                limit = policy.member_execution_limit
                root = _root_claim(record)
                if (config.enabled or policy.owner_mode != MachineMode.PAUSED or policy.admin_mode_override is not None
                        or consent_policy_digest(policy) != consent['policy_sha256'] or limit is None or not limit.active
                        or limit.offer_sha256 != offer['offer_sha256'] or limit.consent_sha256 != consent['consent_sha256']
                        or config.root_uuid != root['root_uuid'] or config.remote_root != root['remote_root']
                        or config.runtime_version != offer['runtime_version'] or config.max_concurrent_units != 1
                        or config.target_concurrent_units != 1 or config.supervisor_startup not in {'boot','logon'}):
                    raise EnrollmentUnavailable()
                now = datetime.now(timezone.utc)
                run = None
                if not trust_first:
                    acceptance_row = session.get(SshAcceptanceRow, run_id)
                    latest_run_id = session.scalar(select(SshAcceptanceRow.run_id).where(
                        SshAcceptanceRow.payload['worker_id'].as_string() == record.machine_id
                    ).order_by(SshAcceptanceRow.created_at.desc(), SshAcceptanceRow.run_id.desc()).limit(1))
                    if latest_run_id != run_id:
                        raise EnrollmentUnavailable()
                    if acceptance_row is None:
                        raise EnrollmentUnavailable()
                    run = SshAcceptanceRun.model_validate(acceptance_row.payload)
                    checks = {c.check_id: c for c in run.checks}
                    required = (set(REQUIRED_CHECK_IDS)-{'concurrency_2','concurrency_3'}) | {'member_admission_context','independent_heartbeat','startup_after_reboot'}
                    now = datetime.now(timezone.utc)
                    expected_context = self.acceptance_context(session, record, config)
                    if (acceptance_row.status != 'passed' or run.run_id != run_id
                            or run.status != AcceptanceStatus.PASSED or run.worker_id != record.machine_id
                            or run.remote_root != config.remote_root or run.concurrency_levels != [1]
                            or run.created_at < datetime.fromisoformat(consent['recorded_at'])
                            or not fresh(run.updated_at, now, maximum_s=3600)
                            or len(checks) != len(run.checks)
                            or any(k not in checks or checks[k].status != AcceptanceStatus.PASSED for k in required)
                            or checks['member_admission_context'].evidence != expected_context):
                        raise EnrollmentUnavailable()
                machine = MachineState.model_validate(session.get(MachineRow, record.machine_id).payload)
                observed_row = session.get(MachineOperationalStatusRow, record.machine_id)
                if observed_row is None:
                    raise EnrollmentUnavailable()
                observed = MachineOperationalStatus.model_validate(observed_row.payload)
                if (machine.machine_id != record.machine_id or machine.owner_user_id != record.owner_user_id
                        or machine.runtime_version != offer['runtime_version'] or machine.metrics.running_units != 0
                        or not machine.metrics.available or not fresh(machine.metrics.observed_at, now)
                        or not fresh(machine.last_heartbeat_at, now)
                        or observed.machine_id != record.machine_id or not observed.observation_consistent
                        or observed.supervisor_reported_concurrent_units != 1
                        or observed.transport_state.value != 'connected' or observed.supervisor_state.value != 'online'
                        or observed.telemetry_state.value != 'live'
                        or any(name not in observed.connection_evidence
                               or not fresh(observed.connection_evidence[name].observed_at, now)
                               or not fresh(observed.connection_evidence[name].supervisor_at, now)
                               or not fresh(observed.connection_evidence[name].metric_at, now)
                               or observed.connection_evidence[name].transport_state.value != 'connected'
                               or not observed.connection_evidence[name].healthy for name in ('ssh','outbound'))):
                    raise EnrollmentUnavailable()
                terminal_states = {state.value for state in (RemoteRunState.COMPLETED, RemoteRunState.FAILED,
                    RemoteRunState.CANCELLED, RemoteRunState.INTERRUPTED)}
                for remote in session.scalars(select(RemoteRunRow).where(RemoteRunRow.machine_id == record.machine_id)):
                    if (remote.state != remote.payload.get('state')
                            or remote.payload.get('state') not in terminal_states):
                        # Unknown, uncertain, reconciling and collecting are not
                        # proof that old execution and result accounting ended.
                        raise EnrollmentUnavailable()
                if trust_first:
                    if trust_readiness_blockers(machine, policy, config, observed, now=now):
                        raise EnrollmentUnavailable()
                    # Trust is a governance decision, not fabricated scientific acceptance.
                    config.execution_provenance.update(admission_policy=TRUST_FIRST,
                        member_admission_enrollment=enrollment_id, member_audit_state='pending')
                    config.hard_capacity_pending_acceptance = True
                    config.conditional_production = 'disabled'
                    effective_run_id = None
                else:
                    config.operational_execution = 'passed'
                    config.startup_after_reboot = 'passed'
                    config.numeric_equivalence = 'passed'
                    config.conditional_production = 'enabled'
                    config.execution_provenance['member_admission_run'] = run.run_id
                    effective_run_id = run.run_id
                config.enabled = True
                config.updated_at = now
                policy.owner_mode = MachineMode.OPEN
                policy.updated_at = now
                for project in scope.project_profiles:
                    identity = 'member-approval-'+hashlib.sha256((enrollment_id+'\0'+project).encode()).hexdigest()[:32]
                    if session.get(ApprovalRow, identity) is not None:
                        raise EnrollmentUnavailable()
                    approval = ApprovalRecord(approval_id=identity, machine_id=record.machine_id,
                        scope=ApprovalScope.PROJECT, subject_id=project,
                        approved_by=f'machine-agent:{record.machine_id}', expires_at=limit.expires_at)
                    session.add(ApprovalRow(approval_id=identity, machine_id=record.machine_id, active=True, payload=_dump(approval)))
                config_row.payload = _dump(config)
                policy_row.payload = _dump(policy)
                result = {'state': 'admitted', 'run_id': effective_run_id, 'admitted_at': now.isoformat(),
                    'offer_sha256': offer['offer_sha256'], 'consent_sha256': consent['consent_sha256'],
                    'grants_execution': True}
                if trust_first:
                    result.update(admission_policy=TRUST_FIRST, audit_state='pending')
                record.member_admission_result = result
                row.payload = _dump(record)
                event = 'member.trust_admitted' if trust_first else 'member.conditionally_admitted'
                self.transport.enrollment._audit(session, event, 'member-admission-runner',
                    enrollment_id, machine_id=record.machine_id, run_id=effective_run_id,
                    offer_sha256=offer['offer_sha256'], consent_sha256=consent['consent_sha256'])
                return result
        return self.repository._retry_sqlite_write(write)

    def revoke(self, enrollment_id: str, *, actor_id: str) -> dict:
        """Stop new admissions/placements, not running computations or identities."""
        def write():
            with self.repository._session() as session, session.begin():
                self.transport.enrollment._lock(session, enrollment_id)
                if UserRole.ADMIN not in self.transport.enrollment._user(session, actor_id).roles:
                    raise EnrollmentUnavailable()
                row = session.get(EnrollmentRow, enrollment_id)
                if row is None:
                    raise EnrollmentUnavailable()
                record = EnrollmentRecord.model_validate(row.payload)
                if record.conditional_admission_offer is None:
                    raise EnrollmentUnavailable()
                if record.member_admission_result and record.member_admission_result.get('state') == 'revoked':
                    return {'state':'revoked', 'running_computation_stopped':False}
                p = session.get(PolicyRow, record.machine_id) if record.machine_id else None
                if p is not None:
                    policy = MachinePolicy.model_validate(p.payload)
                    if policy.member_execution_limit is not None:
                        policy.member_execution_limit.active = False
                        p.payload = _dump(policy)
                record.member_admission_result = {**(record.member_admission_result or {}),
                    'state':'revoked', 'revoked_at':datetime.now(timezone.utc).isoformat(), 'grants_execution':False}
                row.payload = _dump(record)
                self.transport.enrollment._audit(session, 'member.compute_admission_revoked', actor_id, enrollment_id,
                    running_computation_stopped=False, device_credential_revoked=False)
                return {'state':'revoked', 'running_computation_stopped':False}
        return self.repository._retry_sqlite_write(write)
