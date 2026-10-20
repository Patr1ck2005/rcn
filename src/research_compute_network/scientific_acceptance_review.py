"""Explicit operator review of a completed, numerics-only failed manual audit.

The producer report remains FAILED. This authorizes conditional operation with
a visible numerical warning; it does not redefine scientific equivalence.
"""
from __future__ import annotations

from datetime import datetime, timezone
import math
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select, text, update

from .hashing import sha256_value
from .models import (AcceptanceStatus, AuditEvent, JobEnvelope, JobStatus,
    MachineExecutionConfig, MachineOperationalStatus, MachinePolicy, MachineState,
    SshAcceptanceRun, WorkUnitStatus)
from .repository import (EnrollmentRow, EventRow, EventSequenceRow, JobRow,
    MachineExecutionConfigRow, MachineOperationalStatusRow, MachineRow, PolicyRow,
    SshAcceptanceRow, _hydrate_payload, _overlay_job_operational_payload)
from .scientific_acceptance_contract import (CAPSULE_RUNTIME, CAPSULE_SHA256,
    CHECK_IDS, context_for, probe_job)


REVIEW_PREFIX = 'scientific_audit_review_'
REVIEW_KIND = 'manual-numerics-only-conditional-v1'
BASELINES = frozenset({'reference-local.json', 'reference-ssh.json'})
METRICS = ('max_complex_frequency_delta_thz', 'max_q_relative_delta',
           'max_scalar_absolute_delta', 'max_normalized_complex_amplitude_delta')


class ScientificAcceptanceReviewRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    run_id: str = Field(pattern=r'^ssh-science-[0-9a-f]{24}$')
    report_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    reason: str = Field(min_length=1, max_length=4000)

    @field_validator('reason')
    @classmethod
    def nonempty_reason(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError('scientific review requires an explicit reason')
        return value


def manual_review_scope(config, policy) -> bool:
    p = config.execution_provenance
    return bool(p.get('admission_policy') == 'trust_first'
        and p.get('onboarding', '').startswith('manual-ssh-')
        and p.get('owner_consent_reference', '').strip()
        and not config.control_plane_heartbeat_url and not config.machine_token_file
        and policy is not None and policy.member_execution_limit is None
        and not any(p.get(k) for k in p if k.startswith('member_')
                    or k in {'scientific_audit_enrollment', 'scientific_audit_consent_sha256',
                             'scientific_audit_offer_sha256'}))


def execution_identity(config) -> dict:
    """Bind the waiver to this worker, not just a reusable three-point context."""
    p = config.execution_provenance
    fields = ('machine_id', 'transport', 'ssh_host', 'ssh_port', 'ssh_user',
              'pinned_host_key', 'remote_root', 'root_uuid', 'runtime_version',
              'python_executable', 'comsol_root', 'comsol_version', 'expected_hostname',
              'supervisor_startup', 'tunnel_startup', 'control_plane_heartbeat_url',
              'machine_token_file')
    return {**{name: getattr(config, name) for name in fields},
            'admission_policy': p.get('admission_policy'),
            'onboarding': p.get('onboarding'),
            'owner_consent_reference': p.get('owner_consent_reference')}


def review_warning(run_id: str, report_sha256: str, missing_runtime_count: int = 0) -> str:
    warning = (f'SCIENTIFIC NUMERICAL ACCEPTANCE FAILED: administrator conditionally reviewed '
            f'{run_id} (report SHA-256 {report_sha256}). Strict numerical equivalence remains '
            'FAILED; computation and collected artifacts passed. Numerical results require '
            'project-side scientific review. Reboot acceptance remains separately recorded.')
    if missing_runtime_count:
        warning += (f' {missing_runtime_count}/3 historical Attempts have no frozen runtime field; '
                    'runtime evidence is the fixed audit context and current live worker observation.')
    return warning


def reviewed_scientific_failure(config, policy, machine=None) -> bool:
    """Protected metadata waives only this failure while worker context is intact."""
    if config is None or not manual_review_scope(config, policy):
        return False
    p = config.execution_provenance
    try:
        missing_runtime_count = int(p.get(REVIEW_PREFIX+'missing_attempt_runtime_count', '-1'))
        return bool(0 <= missing_runtime_count <= 3
            and p.get(REVIEW_PREFIX+'owner_user_id') == policy.owner_user_id
            and (machine is None or (p.get(REVIEW_PREFIX+'machine_hostname') == machine.hostname
                 and p.get(REVIEW_PREFIX+'owner_user_id') == machine.owner_user_id))
            and p.get('scientific_audit_state') == 'failed'
            and p.get(REVIEW_PREFIX+'kind') == REVIEW_KIND
            and p.get(REVIEW_PREFIX+'run_id') == p.get('scientific_audit_run_id')
            and re.fullmatch(r'ssh-science-[0-9a-f]{24}', p.get(REVIEW_PREFIX+'run_id', ''))
            and p.get(REVIEW_PREFIX+'report_sha256') == p.get('scientific_audit_report_sha256')
            and re.fullmatch(r'[0-9a-f]{64}', p.get(REVIEW_PREFIX+'report_sha256', ''))
            and p.get(REVIEW_PREFIX+'context_sha256') == sha256_value(context_for(config))
            and p.get(REVIEW_PREFIX+'execution_identity_sha256') == sha256_value(execution_identity(config))
            and p.get(REVIEW_PREFIX+'actor_id', '').strip()
            and p.get(REVIEW_PREFIX+'reason', '').strip()
            and p.get(REVIEW_PREFIX+'reviewed_at', '').strip()
            and config.operational_execution == 'passed' and config.numeric_equivalence == 'warning'
            and config.supervisor_startup in {'boot', 'logon'}
            and review_warning(p['scientific_audit_run_id'], p['scientific_audit_report_sha256'],
                               missing_runtime_count)
                in config.capability_warnings)
    except (ValueError, TypeError, KeyError):
        return False


def _validated_report(config, run, job, report_sha256):
    p = config.execution_provenance
    context = context_for(config)
    expected_job = probe_job(config)
    if (p.get('scientific_audit_state') != 'failed'
            or p.get('scientific_audit_run_id') != run.run_id
            or run.status != AcceptanceStatus.FAILED
            or run.worker_id != config.machine_id or run.remote_root != config.remote_root
            or run.concurrency_levels != [1]
            or p.get('scientific_audit_capsule') != CAPSULE_SHA256
            or p.get('scientific_audit_report_sha256') != report_sha256
            or sha256_value(run.model_dump(mode='json')) != report_sha256
            or run.run_id != 'ssh-science-'+expected_job.request_hash[:24]
            or p.get('scientific_audit_job_id') != expected_job.job_id
            or p.get('scientific_audit_request_hash') != expected_job.request_hash):
        raise ValueError('scientific_review_report_binding_changed')
    checks = {check.check_id: check for check in run.checks}
    if len(checks) != len(run.checks) or set(checks) != CHECK_IDS:
        raise ValueError('scientific_review_incomplete_checks')
    if (any(checks[name].status != AcceptanceStatus.PASSED for name in CHECK_IDS-{'scientific_numerics'})
            or checks['scientific_numerics'].status != AcceptanceStatus.FAILED):
        raise ValueError('scientific_review_requires_numerics_only_failure')
    expected_context = {**context, 'job_id': expected_job.job_id,
                        'expected_checks': sorted(CHECK_IDS), 'machine_lifecycle_acceptance': False}
    if checks['scientific_context'].evidence != expected_context:
        raise ValueError('scientific_review_context_changed')
    artifacts = checks['scientific_artifacts'].evidence
    if (artifacts.get('manifest_count') != 3 or not isinstance(artifacts.get('sha256'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', artifacts['sha256'])
            or artifacts.get('reason_code')):
        raise ValueError('scientific_review_artifacts_not_verified')
    comparisons = checks['scientific_numerics'].evidence.get('comparisons')
    if not isinstance(comparisons, dict) or set(comparisons) != BASELINES:
        raise ValueError('scientific_review_two_baselines_required')
    any_failed = False
    for comparison in comparisons.values():
        if not isinstance(comparison, dict) or type(comparison.get('passed')) is not bool:
            raise ValueError('scientific_review_invalid_numerical_evidence')
        points = comparison.get('k_points')
        if (not isinstance(points, list) or len(points) != 3
                or any(not isinstance(point, dict) or type(point.get('k_idx')) is not int for point in points)
                or {point.get('k_idx') for point in points} != {0, 1, 2}):
            raise ValueError('scientific_review_three_points_required')
        for point in points:
            if (point.get('physical_classification_equal') is not True
                    or type(point.get('passed')) is not bool or point.get('error')):
                raise ValueError('scientific_review_physical_classification_changed')
            for key in METRICS:
                value = point.get(key)
                if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
                    raise ValueError('scientific_review_nonfinite_numerical_evidence')
        if comparison['passed'] != all(point['passed'] for point in points):
            raise ValueError('scientific_review_inconsistent_numerical_evidence')
        any_failed = any_failed or not comparison['passed']
    if not any_failed:
        raise ValueError('scientific_review_missing_numerical_failure')
    job_fields = ('job_id', 'request_hash', 'user_id', 'origin_submitter_id',
                  'project_id', 'execution_profile_id', 'record_class', 'resource_mode')
    unit_fields = ('work_unit_id', 'ordinal', 'payload', 'atomic_item_ids', 'resources',
                   'required_capabilities', 'required_machine_id', 'resource_mode', 'max_attempts')
    if (any(getattr(job, name) != getattr(expected_job, name) for name in job_fields)
            or job.status != JobStatus.COMPLETED or len(job.work_units) != 3):
        raise ValueError('scientific_review_original_job_changed')
    missing_runtime = []
    for unit, expected_unit in zip(job.work_units, expected_job.work_units):
        if any(getattr(unit, name) != getattr(expected_unit, name) for name in unit_fields):
            raise ValueError('scientific_review_original_job_changed')
        attempt = unit.attempts[-1] if unit.attempts else None
        if (unit.status != WorkUnitStatus.COMPLETED or unit.assigned_machine_id != config.machine_id
                or unit.required_machine_id != config.machine_id or attempt is None
                or attempt.machine_id != config.machine_id or attempt.state != 'completed'
                or attempt.finished_at is None or attempt.collected_at is None
                or attempt.runtime_version not in {None, CAPSULE_RUNTIME}):
            raise ValueError('scientific_review_completed_collected_units_required')
        if attempt.runtime_version is None:
            missing_runtime.append(attempt.attempt_id)
    expected_scan = {'job_id': job.job_id, 'units': [
        {'unit_id': u.work_unit_id, 'status': u.status.value, 'duration_s': u.actual_duration_s,
         'machine_id': u.assigned_machine_id, 'attempt_count': u.attempt_count} for u in job.work_units]}
    if checks['scientific_scan'].evidence != expected_scan:
        raise ValueError('scientific_review_scan_evidence_changed')
    return context, missing_runtime


def review_scientific_acceptance(repository, machine_id: str, *, run_id: str,
                                report_sha256: str, reason: str, actor_id: str):
    request = ScientificAcceptanceReviewRequest(run_id=run_id, report_sha256=report_sha256, reason=reason)
    if not actor_id.strip():
        raise ValueError('scientific_review_actor_required')

    def write():
        with repository._session() as session, session.begin():
            if repository.engine.dialect.name == 'sqlite':
                session.execute(text('BEGIN IMMEDIATE'))
            row = session.scalar(select(MachineExecutionConfigRow).where(
                MachineExecutionConfigRow.machine_id == machine_id).with_for_update())
            if row is None:
                raise KeyError(f'machine execution config not found: {machine_id}')
            config = MachineExecutionConfig.model_validate(row.payload)
            machine_row = session.get(MachineRow, machine_id)
            policy_row = session.get(PolicyRow, machine_id)
            observed_row = session.get(MachineOperationalStatusRow, machine_id)
            run_row = session.get(SshAcceptanceRow, request.run_id)
            if machine_row is None or policy_row is None or run_row is None:
                raise ValueError('scientific_review_original_evidence_missing')
            machine = MachineState.model_validate(machine_row.payload)
            policy = MachinePolicy.model_validate(policy_row.payload)
            observed = MachineOperationalStatus.model_validate(observed_row.payload) if observed_row else None
            if (not manual_review_scope(config, policy) or session.scalar(select(EnrollmentRow.enrollment_id)
                    .where(EnrollmentRow.payload['machine_id'].as_string() == machine_id).limit(1))):
                raise ValueError('scientific_review_manual_owner_consent_required')
            run = SshAcceptanceRun.model_validate(run_row.payload)
            job_row = session.get(JobRow, config.execution_provenance.get('scientific_audit_job_id', ''))
            if job_row is None or run_row.status != 'failed':
                raise ValueError('scientific_review_original_evidence_missing')
            job = JobEnvelope.model_validate(_hydrate_payload(session,
                _overlay_job_operational_payload(job_row.payload, job_row.operational_payload)))
            context, missing_runtime = _validated_report(config, run, job, request.report_sha256)
            p = config.execution_provenance
            current = {k: v for k, v in p.items() if k.startswith(REVIEW_PREFIX)}
            binding = {REVIEW_PREFIX+'kind': REVIEW_KIND, REVIEW_PREFIX+'run_id': request.run_id,
                REVIEW_PREFIX+'report_sha256': request.report_sha256,
                REVIEW_PREFIX+'context_sha256': sha256_value(context),
                REVIEW_PREFIX+'execution_identity_sha256': sha256_value(execution_identity(config)),
                REVIEW_PREFIX+'owner_user_id': machine.owner_user_id,
                REVIEW_PREFIX+'machine_hostname': machine.hostname,
                REVIEW_PREFIX+'missing_attempt_runtime_count': str(len(missing_runtime)),
                REVIEW_PREFIX+'actor_id': actor_id, REVIEW_PREFIX+'reason': request.reason}
            if current:
                if (any(current.get(k) != v for k, v in binding.items())
                        or not reviewed_scientific_failure(config, policy, machine)):
                    raise ValueError('scientific_review_existing_binding_changed')
                # A replay is observation only; it must not reopen a later pause.
                return config
            if (any(value == 'failed' for value in (config.operational_execution,
                    config.numeric_equivalence, config.startup_after_reboot))
                    or p.get('member_audit_state') == 'failed'):
                raise ValueError('scientific_review_other_known_acceptance_failure')
            if config.supervisor_startup not in {'boot', 'logon'}:
                raise ValueError('scientific_review_automatic_startup_required')
            if config.expected_hostname and config.expected_hostname.casefold() != machine.hostname.casefold():
                raise ValueError('scientific_review_expected_worker_hostname_changed')
            at = datetime.now(timezone.utc)
            config.execution_provenance = {**p, **binding, REVIEW_PREFIX+'reviewed_at': at.isoformat()}
            config.operational_execution = 'passed'
            config.numeric_equivalence = 'warning'
            warning = review_warning(request.run_id, request.report_sha256, len(missing_runtime))
            config.capability_warnings = [*config.capability_warnings, warning]
            from .admission_governance import trust_readiness_blockers
            reasons = trust_readiness_blockers(machine, policy, config, observed, now=at)
            if reasons:
                raise ValueError('scientific_review_execution_prerequisites: '+', '.join(reasons))
            config.enabled = True
            config.conditional_production = 'enabled'
            config.updated_at = at
            row.payload = config.model_dump(mode='json')
            event = AuditEvent(event_type='machine.scientific_acceptance_conditionally_reviewed',
                actor_id=actor_id, subject_type='machine', subject_id=machine_id, details={
                    'run_id': request.run_id, 'job_id': job.job_id, 'report_sha256': request.report_sha256,
                    'context_sha256': binding[REVIEW_PREFIX+'context_sha256'],
                    'execution_identity_sha256': binding[REVIEW_PREFIX+'execution_identity_sha256'],
                    'reason': request.reason, 'original_scientific_status': 'failed',
                    'numeric_equivalence': 'warning', 'operational_execution': 'passed',
                    'startup_after_reboot': config.startup_after_reboot, 'warning': warning,
                    'attempt_runtime_missing': missing_runtime,
                    'runtime_evidence': 'fixed-capsule-context-and-current-live-worker',
                    'original_job_and_report_changed': False, 'capacity_and_policy_changed': False})
            event.sequence = session.execute(update(EventSequenceRow)
                .where(EventSequenceRow.sequence_id == 'global')
                .values(next_sequence=EventSequenceRow.next_sequence+1)
                .returning(EventSequenceRow.next_sequence)).scalar_one()-1
            session.add(EventRow(event_id=event.event_id, event_type=event.event_type,
                subject_type=event.subject_type, subject_id=event.subject_id,
                created_at=event.created_at, sequence=event.sequence, payload=event.model_dump(mode='json')))
            return config

    return repository._retry_sqlite_write(write)
