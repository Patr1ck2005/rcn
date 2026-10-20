"""Reconcile real post-admission acceptance reports; never synthesize a probe.

Uses the existing enrollment, acceptance rows and audit transaction. Missing
producers/reports leave a durable pending audit, without reintroducing approval
as a prerequisite for using a ready member. No remote commands run here.
"""
from datetime import datetime, timezone

from sqlalchemy import select

from .admission_governance import TRUST_FIRST, offer_governance, trust_first_execution
from .connection_health import fresh
from .member_admission_contract import canonical_digest
from .member_admission import _dump, _stored_consent
from .member_admission_invitation import checked_offer
from .member_enrollment import EnrollmentUnavailable
from .models import AcceptanceStatus, EnrollmentRecord, MachineExecutionConfig, SshAcceptanceRun
from .repository import EnrollmentRow, MachineExecutionConfigRow, SshAcceptanceRow
from .ssh_acceptance import REQUIRED_CHECK_IDS


def _reconcile_scientific_report(admissions, session, record, config, config_row) -> dict:
    """Consume only an exact producer-bound report, not the latest arbitrary PASS."""
    from .hashing import sha256_value
    from .scientific_acceptance_contract import CHECK_IDS, context_for
    p = config.execution_provenance
    run_id = p.get('scientific_audit_run_id')
    row = session.get(SshAcceptanceRow, run_id)
    if row is None:
        return {'state':'pending','reason_code':'scientific_report_not_available'}
    run = SshAcceptanceRun.model_validate(row.payload)
    consent = _stored_consent(record); offer = checked_offer(record)
    try:
        expected = {**context_for(config), 'job_id': p['scientific_audit_job_id'],
                    'expected_checks': sorted(CHECK_IDS), 'machine_lifecycle_acceptance': False}
    except (ValueError, KeyError):
        return {'state':'pending','reason_code':'scientific_report_binding_missing'}
    checks = {c.check_id:c for c in run.checks}
    digest = sha256_value(run.model_dump(mode='json'))
    if (row.status != run.status.value or run.run_id != run_id or run.worker_id != record.machine_id
            or run.remote_root != config.remote_root or run.concurrency_levels != [1]
            or len(checks) != len(run.checks) or set(checks) != CHECK_IDS
            or checks['scientific_context'].evidence != expected
            or checks['scientific_context'].status != AcceptanceStatus.PASSED
            or p.get('scientific_audit_enrollment') != record.enrollment_id
            or p.get('scientific_audit_consent_sha256') != consent['consent_sha256']
            or p.get('scientific_audit_offer_sha256') != offer['offer_sha256']
            or run.created_at < datetime.fromisoformat(consent['recorded_at'])
            or digest != p.get('scientific_audit_report_sha256')):
        return {'state':'pending','reason_code':'scientific_report_not_bound'}
    state = run.status.value
    if (state not in {'passed','failed'} or p.get('scientific_audit_state') != state
            or (state == 'passed' and any(c.status != AcceptanceStatus.PASSED for c in checks.values()))
            or (state == 'failed' and not any(c.status == AcceptanceStatus.FAILED for c in checks.values()))):
        return {'state':'pending','reason_code':'scientific_report_incomplete'}
    prior = record.member_admission_result
    science = {'state': state, 'run_id': run_id, 'report_sha256': digest, 'scope': 'scientific-only'}
    if prior.get('scientific_audit') == science:
        return {'state': prior.get('audit_state',state), 'run_id': run_id, 'changed':False, 'scope':'scientific-only'}
    # A success cannot erase a known failed lifecycle review or reopen a stop.
    effective = 'failed' if p.get('member_audit_state') == 'failed' else state
    if effective == 'failed':
        config.enabled = False; config.conditional_production = 'disabled'
    config.execution_provenance.update(member_audit_state=effective, member_audit_scope='scientific-only',
                                       member_audit_run=run_id)
    config.updated_at = datetime.now(timezone.utc)
    record.member_admission_result = {**prior, 'audit_state':effective, 'audit_scope':'scientific-only',
        'audit_run_id':run_id, 'audit_report_sha256':digest, 'audit_checked_at':config.updated_at.isoformat(),
        'scientific_audit':science}
    session.get(EnrollmentRow, record.enrollment_id).payload = _dump(record)
    config_row.payload = _dump(config)
    admissions.transport.enrollment._audit(session, 'member.async_scientific_acceptance_'+state,
        'member-admission-auditor',record.enrollment_id,machine_id=record.machine_id,
        run_id=run_id,report_sha256=digest,scope='scientific-only',interrupts_running_work=False)
    return {'state':effective, 'run_id':run_id, 'changed':True, 'scope':'scientific-only'}


def reconcile_member_audit(admissions, enrollment_id: str) -> dict:
    repository = admissions.repository

    def write():
        with repository._session() as session, session.begin():
            admissions.transport.enrollment._lock(session, enrollment_id)
            row = session.get(EnrollmentRow, enrollment_id)
            if row is None:
                raise EnrollmentUnavailable()
            record = EnrollmentRecord.model_validate(row.payload)
            prior = record.member_admission_result
            if (record.revoked_at is not None or not isinstance(prior, dict)
                    or prior.get('state') != 'admitted' or prior.get('admission_policy') != TRUST_FIRST):
                return {'state': 'not_applicable'}
            offer = checked_offer(record)
            if offer_governance(offer) != TRUST_FIRST:
                raise EnrollmentUnavailable()
            config_row = session.get(MachineExecutionConfigRow, record.machine_id)
            if config_row is None:
                return {'state': 'pending', 'reason_code': 'execution_configuration_missing'}
            config = MachineExecutionConfig.model_validate(config_row.payload)
            if (not trust_first_execution(config)
                    or config.execution_provenance.get('member_admission_enrollment') != enrollment_id):
                return {'state': 'pending', 'reason_code': 'admission_binding_changed'}
            science_result = None
            if config.execution_provenance.get('scientific_audit_run_id'):
                science_result = _reconcile_scientific_report(admissions, session, record, config, config_row)
                prior = record.member_admission_result
            latest = session.scalar(select(SshAcceptanceRow).where(
                SshAcceptanceRow.payload['worker_id'].as_string() == record.machine_id,
                (SshAcceptanceRow.payload['checks'][0]['check_id'].as_string() != 'scientific_context')
                | SshAcceptanceRow.payload['checks'][0]['check_id'].as_string().is_(None)
            ).order_by(SshAcceptanceRow.created_at.desc(), SshAcceptanceRow.run_id.desc()).limit(1))
            if latest is None:
                return science_result or {'state': 'pending', 'reason_code': 'acceptance_report_not_available'}
            run = SshAcceptanceRun.model_validate(latest.payload)
            report_sha256 = canonical_digest(_dump(run))
            if (prior.get('audit_run_id') == run.run_id
                    and prior.get('audit_report_sha256') == report_sha256
                    and prior.get('audit_state') in {'passed', 'failed'}):
                return {'state': prior['audit_state'], 'run_id': run.run_id, 'changed': False}
            context = admissions.acceptance_context(session, record, config)
            consent = _stored_consent(record)
            checks = {check.check_id: check for check in run.checks}
            required = (set(REQUIRED_CHECK_IDS) - {'concurrency_2', 'concurrency_3'}) | {
                'member_admission_context', 'independent_heartbeat', 'startup_after_reboot'}
            at = datetime.now(timezone.utc)
            if (latest.run_id != run.run_id or latest.status != run.status.value
                    or run.worker_id != record.machine_id or run.remote_root != config.remote_root
                    or run.concurrency_levels != [1] or len(checks) != len(run.checks)
                    or run.created_at < datetime.fromisoformat(consent['recorded_at'])
                    or 'member_admission_context' not in checks
                    or checks['member_admission_context'].evidence != context):
                return science_result or {'state': 'pending', 'reason_code': 'acceptance_evidence_not_bound'}
            state = None
            if (run.status == AcceptanceStatus.PASSED
                    and fresh(run.updated_at, at, maximum_s=3600)
                    and all(key in checks and checks[key].status == AcceptanceStatus.PASSED for key in required)):
                state = 'passed'
            elif (run.status == AcceptanceStatus.FAILED
                    and any(key in checks and checks[key].status == AcceptanceStatus.FAILED for key in required)):
                state = 'failed'
            if state is None:
                return science_result or {'state': 'pending', 'reason_code': 'full_acceptance_incomplete'}
            if science_result and science_result.get('state') == 'failed':
                state = 'failed'
            if prior.get('audit_run_id') == run.run_id and prior.get('audit_state') == state:
                return {'state': state, 'run_id': run.run_id, 'changed': False}
            if state == 'failed':
                # Stop new dispatch only; never cancel science or mutate owner mode.
                config.enabled = False
                config.conditional_production = 'disabled'
            else:
                config.operational_execution = 'passed'
                config.startup_after_reboot = 'passed'
                config.numeric_equivalence = 'passed'
                config.hard_capacity_pending_acceptance = False
                # Acceptance is not permission to reverse an operator/owner stop.
                if config.enabled:
                    config.conditional_production = 'enabled'
            config.execution_provenance['member_audit_state'] = state
            config.execution_provenance['member_audit_scope'] = 'full-lifecycle'
            config.execution_provenance['member_audit_run'] = run.run_id
            config.updated_at = at
            record.member_admission_result = {**prior, 'audit_state': state, 'audit_scope': 'full-lifecycle',
                'audit_run_id': run.run_id, 'audit_report_sha256': report_sha256,
                'audit_checked_at': at.isoformat()}
            row.payload = _dump(record)
            config_row.payload = _dump(config)
            admissions.transport.enrollment._audit(session, 'member.async_acceptance_' + state,
                'member-admission-auditor', enrollment_id, machine_id=record.machine_id,
                run_id=run.run_id, interrupts_running_work=False)
            return {'state': state, 'run_id': run.run_id, 'changed': True}

    return repository._retry_sqlite_write(write)
