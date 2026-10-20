"""Resumable scientific acceptance through the existing Job/Dispatcher/spool.

Works for explicitly trust-admitted manual machines and signed invitations.
No network execution happens in this producer: it publishes fixed inputs and
observes ordinary dispatched Jobs. Full machine fault/reboot acceptance stays
separate and is never manufactured by a successful scientific report.
"""
from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import socket

from sqlalchemy import select, text, update

from .admission_governance import trust_first_execution
from .hashing import sha256_file, sha256_value
from .models import (AcceptanceCheck, AcceptanceStatus, ApprovalRecord, ApprovalScope, AuditEvent,
    JobStatus, MachineExecutionConfig, ProjectGrant, SshAcceptanceRun, WorkUnitStatus)
from .origin import BUNDLE_BUILD_METADATA_MARGIN_BYTES, OriginSpool
from .origin_transfer import managed_path
from .paths import ControlPlanePaths
from .repository import (ApprovalRow, EventRow, EventSequenceRow, MachineExecutionConfigRow,
    ProjectGrantRow, SshAcceptanceRow)
from .scientific_acceptance_contract import (ACTOR, CAPSULE_SHA256, CHECK_IDS, PROFILE, PROJECT,
    context_for, materialize_capsule, probe_job, publish_immutable)
from .storage_roots import StorageRootError
from .volume_budget import VolumeBudget, VolumeBudgetError


def _audit(session, kind, machine_id, **details):
    event = AuditEvent(event_type=kind, actor_id=ACTOR, subject_type='machine', subject_id=machine_id, details=details)
    event.sequence = session.execute(update(EventSequenceRow).where(EventSequenceRow.sequence_id=='global')
        .values(next_sequence=EventSequenceRow.next_sequence+1).returning(EventSequenceRow.next_sequence)).scalar_one()-1
    session.add(EventRow(event_id=event.event_id, event_type=kind, subject_type='machine',
        subject_id=machine_id, created_at=event.created_at, sequence=event.sequence, payload=event.model_dump(mode='json')))


@contextmanager
def _lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a+b') as handle:
        handle.seek(0, 2)
        if handle.tell()==0:
            handle.write(b'0');handle.flush()
        handle.seek(0)
        try:
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            handle.seek(0)
            if os.name=='nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _member_science_binding(repository, config, policy, *, session=None) -> dict:
    """Bind new invited probes to the same signed consent; manual nodes opt in separately."""
    identity = config.execution_provenance.get('member_admission_enrollment')
    if not identity:
        return {}
    from .member_admission import _stored_consent
    from .member_admission_invitation import checked_offer
    from contextlib import nullcontext
    from .models import EnrollmentRecord
    from .repository import EnrollmentRow
    with (nullcontext(session) if session is not None else repository._session()) as current:
        row = current.get(EnrollmentRow, identity)
        record = EnrollmentRecord.model_validate(row.payload) if row is not None else None
    limit = policy.member_execution_limit
    if (record is None or record.revoked_at is not None or record.machine_id != config.machine_id
            or not record.member_admission_result or record.member_admission_result.get('state') != 'admitted'
            or limit is None or not limit.is_active() or limit.enrollment_id != identity):
        raise ValueError('scientific_acceptance_member_authority_changed')
    consent = _stored_consent(record); offer = checked_offer(record)
    if limit.consent_sha256 != consent['consent_sha256'] or limit.offer_sha256 != offer['offer_sha256']:
        raise ValueError('scientific_acceptance_member_consent_changed')
    return {'scientific_audit_enrollment': identity,
            'scientific_audit_consent_sha256': consent['consent_sha256'],
            'scientific_audit_offer_sha256': offer['offer_sha256']}


class ScientificAcceptanceProducer:
    def __init__(self, service, *, state_root: Path, origin_spool: Path | None=None):
        self.service=service;self.repository=service.repository;self.state_root=Path(state_root)
        self._explicit_origin_root=Path(origin_spool) if origin_spool is not None else None
        self.origin_root=(self._explicit_origin_root if self._explicit_origin_root is not None
                          else ControlPlanePaths.from_root(self.state_root).origin_spool)
        self.cursor=''

    def _origin_spool(self, *, write=False):
        if self._explicit_origin_root is not None:
            # An explicit origin remains the caller's isolated/legacy spool.
            return OriginSpool(self._explicit_origin_root)
        paths=ControlPlanePaths.from_root(self.state_root)
        selected=paths.origin_spool
        binding=paths.storage_registry.binding('origin_spool')
        def validate():
            current=ControlPlanePaths.from_root(self.state_root)
            if (current.origin_spool!=selected
                    or current.storage_registry.binding('origin_spool')!=binding):
                raise StorageRootError('storage_binding_changed','scientific acceptance storage binding changed')
            return (current.validate_storage_write('origin_spool') if write
                    else current.validate_storage('origin_spool'))
        validate()
        self.origin_root=selected
        return OriginSpool(selected,storage_validator=validate)

    def _volume_budget(self):
        database=self.repository.engine.url.database
        if self.repository.engine.dialect.name!='sqlite' or not database or database==':memory:':
            return None
        # The service may have an explicit DB URL distinct from paths.database.
        return VolumeBudget(database)

    def _publish_inputs(self, job, inputs, runtime_version):
        readable=self._origin_spool()
        missing=[]
        for unit in job.work_units:
            path=readable.outgoing_path(job,unit)
            readable._guard_storage()
            if path.is_file():
                descriptor=readable.validate(job,unit)
                if descriptor.runtime_version!=runtime_version:
                    raise ValueError('scientific_acceptance_input_runtime_changed')
            else:
                missing.append(unit)
        if not missing:return
        spool=self._origin_spool(write=True)
        budget=self._volume_budget()
        claim=None
        if budget is not None:
            # Bound all missing ZIP writes, including deflate expansion and metadata.
            sizes=[record.size_bytes for record in job.input_manifest]
            per_unit=sum(size+((size+7)>>3)+((size+63)>>6)+11 for size in sizes)
            required=len(missing)*(per_unit+BUNDLE_BUILD_METADATA_MARGIN_BYTES)
            spool._guard_storage()
            claim=budget.reserve(spool.root,required,holder_kind='scientific_acceptance_inputs',holder_key=job.job_id)
        try:
            for unit in missing:
                spool._guard_storage()
                spool.publish_comsol(job=job,project_root=inputs,project_yaml=inputs/'project.yaml',
                    scan_spec=inputs/'test_batch_3pt.yaml',template=inputs/'template.mph',
                    runtime_version=runtime_version,work_unit_id=unit.work_unit_id)
        finally:
            if claim is not None:
                # All publication is synchronous: no child writer outlives this call.
                budget.release(claim,writer_stopped=True,evidence='scientific input ZIP publisher returned or raised')

    @staticmethod
    def _storage_pending(exc, machine_id, run_id, job_id):
        return {'state':'pending','reason_code':exc.reason_code,'machine_id':machine_id,
                'run_id':run_id,'job_id':job_id}

    def tick(self) -> dict:
        # A bounded round-robin selector cannot enroll or touch legacy machines.
        configs=[]
        for c in self.repository.list_machine_execution_configs():
            if not trust_first_execution(c):continue
            p=c.execution_provenance
            if p.get('scientific_audit_state') in {'passed','failed'}:
                run_id=p.get('scientific_audit_run_id','')
                if run_id.startswith('ssh-science-') and not (self.state_root/'scientific-acceptance'/'reports'/run_id/'acceptance-report.json').is_file():
                    configs.append(c)
            elif c.enabled or p.get('scientific_audit_job_id'):
                configs.append(c)
        configs.sort(key=lambda c:c.machine_id)
        candidate=next((c for c in configs if c.machine_id>self.cursor),configs[0] if configs else None)
        if candidate is None:return {'state':'idle'}
        self.cursor=candidate.machine_id
        return self.tick_machine(candidate.machine_id)

    def tick_machine(self, machine_id: str) -> dict:
        key=hashlib.sha256(machine_id.encode()).hexdigest()
        with _lock(self.state_root/'scientific-acceptance'/('lock-'+key)) as acquired:
            if not acquired:return {'state':'busy','machine_id':machine_id}
            config=self.repository.get_machine_execution_config(machine_id)
            if config is None or not trust_first_execution(config):return {'state':'not_applicable'}
            terminal=config.execution_provenance.get('scientific_audit_state')
            if terminal in {'passed','failed'}:
                self._report(config.execution_provenance.get('scientific_audit_run_id'))
                return {'state':terminal,'job_id':config.execution_provenance.get('scientific_audit_job_id')}
            bound = bool(config.execution_provenance.get('scientific_audit_job_id'))
            if not config.enabled and not bound:
                return {'state':'pending','reason_code':'machine_execution_disabled'}
            machine=self.repository.get_machine(machine_id);policy=self.repository.get_policy(machine_id)
            if machine is None or policy is None:return {'state':'pending','reason_code':'machine_policy_missing'}
            limit=policy.member_execution_limit
            consent_active = not limit or limit.is_active()
            if not consent_active and not bound:
                return {'state':'pending','reason_code':'member_consent_inactive'}
            if config.comsol_version!='6.4' or 'comsol-6.4' not in machine.capabilities:
                return {'state':'pending','reason_code':'fixed_scientific_probe_requires_comsol_6_4'}
            if not config.execution_provenance.get('scientific_audit_job_id'):
                config=config.model_copy(deep=True)
                threads=min(4,policy.effective_cpu_cap(machine.total_cpus))
                if threads<1:return {'state':'pending','reason_code':'scientific_acceptance_cpu_budget'}
                config.execution_provenance['scientific_audit_threads']=str(threads)
                config.execution_provenance.update(_member_science_binding(self.repository, config, policy))
                if limit and not any(PROFILE in profiles for profiles in limit.project_profiles.values()):
                    return {'state':'pending','reason_code':'scientific_acceptance_profile_not_consented'}
                memory_cap = min(policy.max_memory_mb, machine.total_memory_mb,
                                 limit.max_memory_mb if limit else policy.max_memory_mb)
                if memory_cap < 8192:
                    return {'state':'pending','reason_code':'scientific_acceptance_memory_budget'}
            try:
                inputs=materialize_capsule(self.state_root)
                job=probe_job(config)
            except (OSError, ValueError):
                # A packaging failure does not forge a failed computation.
                return {'state':'blocked','reason_code':'fixed_scientific_capsule_unavailable'}
            run_id=self._bind(config,job)
            current=self.repository.get_job(job.job_id)
            if current is None:
                if not config.enabled or not consent_active:
                    return {'state':'pending','reason_code':'scientific_acceptance_execution_paused'}
                current=self.service.submit(job,actor_id=ACTOR)
                if current.job_id!=job.job_id or current.request_hash!=job.request_hash:
                    raise ValueError('scientific_acceptance_submission_identity_changed')
            elif current.request_hash!=job.request_hash or current.user_id!=ACTOR:
                raise ValueError('scientific_acceptance_job_collision')
            has_failed_unit=any(u.status in {WorkUnitStatus.FAILED_TERMINAL,WorkUnitStatus.CANCELLED}
                                for u in current.work_units)
            if not has_failed_unit and current.status not in {JobStatus.COMPLETED,JobStatus.FAILED_TERMINAL,JobStatus.CANCELLED}:
                if not config.enabled or not consent_active:
                    return {'state':'pending','reason_code':'scientific_acceptance_execution_paused','job_id':job.job_id}
                try:
                    self._publish_inputs(current,inputs,config.runtime_version)
                except (StorageRootError,VolumeBudgetError) as exc:
                    return self._storage_pending(exc,machine_id,run_id,current.job_id)
                except OSError:
                    # The data disk can disappear between a guard and an IO call.
                    try:
                        self._origin_spool()
                    except StorageRootError as exc:
                        return self._storage_pending(exc,machine_id,run_id,current.job_id)
                    raise
                return {'state':'running','machine_id':machine_id,'run_id':run_id,'job_id':current.job_id,
                        'completed_units':sum(u.status==WorkUnitStatus.COMPLETED for u in current.work_units)}
            checks=[]
            execution_ok=(current.status==JobStatus.COMPLETED and len(current.work_units)==3
                          and all(u.status==WorkUnitStatus.COMPLETED for u in current.work_units))
            checks.append(self._check('scientific_scan',execution_ok,job_id=current.job_id,
                units=[{'unit_id':u.work_unit_id,'status':u.status.value,'duration_s':u.actual_duration_s,
                        'machine_id':u.assigned_machine_id,'attempt_count':u.attempt_count} for u in current.work_units]))
            if execution_ok:
                try:
                    spool=self._origin_spool()
                    manifests=self._verified_manifests(spool,current,machine_id)
                    combined={'files':[entry for m in manifests for entry in m['files']]}
                    destination=self.state_root/'scientific-acceptance'/'reports'/run_id
                    destination.mkdir(parents=True,exist_ok=True)
                    merged=destination/'merged-manifest.json'
                    self._write_once(merged,(json.dumps(combined,sort_keys=True,allow_nan=False)+'\n').encode())
                    checks.append(self._check('scientific_artifacts',True,manifest_count=len(manifests),
                                               sha256=sha256_file(merged)))
                    from .ssh_acceptance import compare_three_point_manifests
                    comparisons={name:compare_three_point_manifests(inputs/name,merged)
                                 for name in ('reference-local.json','reference-ssh.json')}
                    checks.append(self._check('scientific_numerics',all(v['passed'] for v in comparisons.values()),
                                               comparisons=comparisons))
                except (StorageRootError,VolumeBudgetError) as exc:
                    return self._storage_pending(exc,machine_id,run_id,current.job_id)
                except (OSError, ValueError, KeyError, TypeError, ImportError, ArithmeticError) as exc:
                    checks.append(self._check('scientific_artifacts',False,reason_code='artifact_or_comparator_validation_failed',
                                              error_type=type(exc).__name__))
                    checks.append(self._check('scientific_numerics',False,reason_code='no_verified_numerical_comparison'))
            else:
                checks.extend([self._check('scientific_artifacts',False,reason_code='scan_not_completed'),
                               self._check('scientific_numerics',False,reason_code='scan_not_completed')])
            passed=all(c.status==AcceptanceStatus.PASSED for c in checks)
            self._finish(config,run_id,current,checks,passed)
            self._report(run_id)
            return {'state':'passed' if passed else 'failed','machine_id':machine_id,'run_id':run_id,'job_id':current.job_id}

    @staticmethod
    def _check(identity,passed,**evidence):
        return AcceptanceCheck(check_id=identity,label=identity,
             status=AcceptanceStatus.PASSED if passed else AcceptanceStatus.FAILED,evidence=evidence)

    def _bind(self, config, job):
        context=context_for(config);run_id='ssh-science-'+job.request_hash[:24]
        def write():
            with self.repository._session() as session,session.begin():
                if self.repository.engine.dialect.name=='sqlite':session.execute(text('BEGIN IMMEDIATE'))
                row=session.scalar(select(MachineExecutionConfigRow).where(
                    MachineExecutionConfigRow.machine_id==config.machine_id).with_for_update())
                latest=MachineExecutionConfig.model_validate(row.payload)
                if not latest.execution_provenance.get('scientific_audit_job_id'):
                    from .repository import PolicyRow, MachineRow
                    from .models import MachinePolicy, MachineState
                    policy=MachinePolicy.model_validate(session.get(PolicyRow,config.machine_id).payload)
                    machine=MachineState.model_validate(session.get(MachineRow,config.machine_id).payload)
                    if context['cpu_threads']>policy.effective_cpu_cap(machine.total_cpus):
                        raise ValueError('scientific_acceptance_cpu_budget_changed')
                    if not latest.enabled:
                        raise ValueError('scientific_acceptance_execution_disabled')
                    latest.execution_provenance['scientific_audit_threads']=str(context['cpu_threads'])
                    latest.execution_provenance.update(_member_science_binding(self.repository, latest, policy, session=session))
                if not trust_first_execution(latest) or context_for(latest)!=context:
                    raise ValueError('scientific_acceptance_authority_changed')
                p=latest.execution_provenance
                if p.get('scientific_audit_job_id'):
                    if p['scientific_audit_job_id']!=job.job_id or p.get('scientific_audit_request_hash')!=job.request_hash:
                        raise ValueError('scientific_acceptance_binding_changed')
                    if session.get(SshAcceptanceRow,run_id) is None:raise ValueError('scientific_acceptance_run_missing')
                    return run_id
                grant=session.get(ProjectGrantRow,PROJECT)
                if grant is None:
                    value=ProjectGrant(project_id=PROJECT,owner_user_id=ACTOR,approved=True,
                         allowed_profiles={PROFILE},max_running_units=1,max_queued_units=2000)
                    session.add(ProjectGrantRow(project_id=PROJECT,approved=True,payload=value.model_dump(mode='json')))
                else:
                    value=ProjectGrant.model_validate(grant.payload)
                    if not value.approved or value.owner_user_id!=ACTOR or value.authorized_user_ids or value.allowed_profiles!={PROFILE}:
                        raise ValueError('scientific_acceptance_reserved_project_changed')
                approval_id='science-approval-'+hashlib.sha256(config.machine_id.encode()).hexdigest()[:32]
                approval=session.get(ApprovalRow,approval_id)
                if approval is None:
                    a=ApprovalRecord(approval_id=approval_id,machine_id=config.machine_id,
                        scope=ApprovalScope.PROJECT,subject_id=PROJECT,approved_by=ACTOR)
                    session.add(ApprovalRow(approval_id=a.approval_id,machine_id=a.machine_id,active=True,payload=a.model_dump(mode='json')))
                else:
                    a=ApprovalRecord.model_validate(approval.payload)
                    if not a.is_active() or a.machine_id!=config.machine_id or a.subject_id!=PROJECT:
                        raise ValueError('scientific_acceptance_owner_scope_changed')
                run=SshAcceptanceRun(run_id=run_id,worker_id=config.machine_id,remote_root=config.remote_root,
                    worker_hostname='',coordinator_hostname=socket.gethostname(),concurrency_levels=[1],status=AcceptanceStatus.RUNNING,
                    checks=[self._check('scientific_context',True,**context,job_id=job.job_id,
                       expected_checks=sorted(CHECK_IDS),machine_lifecycle_acceptance=False)])
                session.add(SshAcceptanceRow(run_id=run_id,status=run.status.value,created_at=run.created_at,payload=run.model_dump(mode='json')))
                latest.execution_provenance={**p,'scientific_audit_job_id':job.job_id,'scientific_audit_request_hash':job.request_hash,
                    'scientific_audit_run_id':run_id,'scientific_audit_capsule':CAPSULE_SHA256,'scientific_audit_state':'queued'}
                row.payload=latest.model_dump(mode='json')
                _audit(session,'machine.scientific_acceptance_queued',config.machine_id,run_id=run_id,job_id=job.job_id,
                       capsule_sha256=CAPSULE_SHA256,compute_protocol_changed=False)
                return run_id
        return self.repository._retry_sqlite_write(write)

    def _verified_manifests(self, spool, job, machine_id):
        manifests=[]
        for unit in job.work_units:
            attempts=[a for a in unit.attempts if a.machine_id==machine_id and a.state=='completed']
            if not attempts or unit.assigned_machine_id!=machine_id:
                raise ValueError('scientific_acceptance_wrong_execution_machine')
            attempt=attempts[-1]
            artifact=self.repository.get_artifact_manifest(unit.work_unit_id)
            if artifact is None or artifact.job_id!=job.job_id:raise ValueError('scientific_acceptance_manifest_missing')
            folder=spool.incoming_path(job,unit,attempt.attempt_id)
            selected=[]
            for record in artifact.files:
                name=PurePosixPath(record.relative_path)
                if name.is_absolute() or '..' in name.parts or '\\' in record.relative_path:
                    raise ValueError('scientific_acceptance_artifact_path')
                def checked_path():
                    spool._guard_storage()
                    return managed_path(folder,record.relative_path)
                try:
                    path=checked_path()
                    if (not path.is_file() or checked_path().stat().st_size!=record.size_bytes
                            or sha256_file(checked_path())!=record.sha256):
                        raise ValueError('scientific_acceptance_artifact_integrity')
                    if path.name == f'chunk_{unit.ordinal:03d}_manifest.json':
                        if checked_path().stat().st_size>2*1024*1024:raise ValueError('scientific_acceptance_manifest_bounds')
                        selected.append(json.loads(checked_path().read_text(encoding='utf-8-sig')))
                except OSError:
                    # Distinguish an unavailable configured disk from corrupt bytes.
                    spool._guard_storage()
                    raise
            if len(selected)!=1:raise ValueError('scientific_acceptance_raw_manifest_ambiguous')
            expected=unit.ordinal
            entries=selected[0].get('files',[])
            if (len(entries)!=21 or any(row.get('k_idx')!=expected for row in entries)
                    or {row.get('band_idx') for row in entries}!=set(range(21))):
                raise ValueError('scientific_acceptance_atomic_coverage')
            manifests.append(selected[0])
        return manifests

    def _finish(self, config, run_id, job, checks, passed):
        def write():
            with self.repository._session() as session,session.begin():
                if self.repository.engine.dialect.name=='sqlite':session.execute(text('BEGIN IMMEDIATE'))
                row=session.scalar(select(MachineExecutionConfigRow).where(
                    MachineExecutionConfigRow.machine_id==config.machine_id).with_for_update())
                latest=MachineExecutionConfig.model_validate(row.payload)
                if context_for(latest)!=context_for(config) or latest.execution_provenance.get('scientific_audit_job_id')!=job.job_id:
                    raise ValueError('scientific_acceptance_completion_context_changed')
                r=session.get(SshAcceptanceRow,run_id);run=SshAcceptanceRun.model_validate(r.payload)
                if run.status in {AcceptanceStatus.PASSED,AcceptanceStatus.FAILED}:return
                original=[c for c in run.checks if c.check_id=='scientific_context']
                if len(original)!=1:raise ValueError('scientific_acceptance_context_missing')
                unique={c.check_id:c for c in checks}
                if set(unique)!=CHECK_IDS-{'scientific_context'}:raise ValueError('scientific_acceptance_incomplete_report')
                run.checks=original+list(unique.values());run.status=AcceptanceStatus.PASSED if passed else AcceptanceStatus.FAILED
                run.updated_at=datetime.now(timezone.utc)
                run.report_path='scientific-acceptance/reports/'+run_id+'/acceptance-report.json'
                r.status=run.status.value;r.payload=run.model_dump(mode='json')
                latest.execution_provenance={**latest.execution_provenance,
                    'scientific_audit_state':'passed' if passed else 'failed',
                    'scientific_audit_report_sha256':sha256_value(run.model_dump(mode='json'))}
                latest.updated_at = run.updated_at
                if passed:
                    latest.operational_execution='passed';latest.numeric_equivalence='passed'
                    # Scientific success is not proof of boot/startup/cancellation.
                else:
                    latest.enabled=False;latest.conditional_production='disabled'
                row.payload=latest.model_dump(mode='json')
                _audit(session,'machine.scientific_acceptance_'+('passed' if passed else 'failed'),config.machine_id,
                     run_id=run_id,job_id=job.job_id,running_jobs_interrupted=False,scientific_only=True)
        self.repository._retry_sqlite_write(write)

    @staticmethod
    def _write_once(path, raw):
        publish_immutable(path, raw)

    def _report(self, run_id):
        if not run_id:return
        import re
        if not re.fullmatch(r'ssh-science-[0-9a-f]{24}',run_id):
            raise ValueError('scientific_acceptance_report_identity')
        run=self.repository.get_ssh_acceptance_run(run_id)
        if run is None or run.status not in {AcceptanceStatus.PASSED,AcceptanceStatus.FAILED}:return
        root=self.state_root/'scientific-acceptance'/'reports'/run_id;root.mkdir(parents=True,exist_ok=True)
        self._write_once(root/'acceptance-report.json',(run.model_dump_json(indent=2)+'\n').encode())
