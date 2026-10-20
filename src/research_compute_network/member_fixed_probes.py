"""Real fixed-profile member probes with durable identity and bounded iteration.

This producer runs only the two packaged, nonscientific acceptance tasks. It
never marks a whole machine accepted, installs a service, alters capacity, or
substitutes these results for COMSOL/cancellation/reboot/recovery evidence.
"""
from __future__ import annotations

from .admission_governance import consent_policy_digest

from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tempfile
from uuid import uuid4
import zipfile

from sqlalchemy import select

from . import member_registration as storage
from .member_admission import MemberAdmissions, _stored_consent
from .member_admission_contract import canonical_digest
from .member_admission_invitation import checked_offer, validate_offer_scope
from .member_enrollment import EnrollmentUnavailable
from .member_relay import _root_claim
from .models import (AcceptanceCheck, AcceptanceStatus, Assignment, EnrollmentRecord, JobEnvelope,
    MachineAgentCredential, MachineExecutionConfig, MachineMode, MachinePolicy, RemoteRunRecord,
    RemoteRunState, SshAcceptanceRun, UserRole, WorkUnit, ResourceRequest)
from .profiles import SAFE_FAKE_TASK_V1, PROJECT_WORKER_V1
from .repository import (EnrollmentRow, MachineCredentialRow, MachineExecutionConfigRow, PolicyRow,
    SshAcceptanceRow, RemoteRunRow)
from .runtime_policy import STABLE_RUNTIME_VERSION
from .member_release_catalog import selected_center_release
from .member_probe_transport import MemberProbeTransport
from .ssh_bundle import build_safe_fake_unit_bundle, build_project_worker_unit_bundle

KINDS = ('safe_fake_task', 'project_worker_task')
TERMINAL = {'completed', 'failed', 'cancelled', 'interrupted'}
JOURNAL = 'fixed-probes.json'


class ProbeUnavailable(RuntimeError):
    """Fixed non-secret reason; no request body or credential is exposed."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _aware(value):
    at = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if at.tzinfo is None:
        raise ValueError('timestamp requires timezone')
    return at


class MemberFixedProbeRunner:
    def __init__(self, service, *, state_root: Path, verification_root: Path, transport_factory=None, runtime_verifier=None):
        self.service = service
        self.runtime_verifier = runtime_verifier
        self.repository = service.repository
        self.state_root = Path(state_root).absolute()
        self.admissions = MemberAdmissions(self.repository, verification_root=verification_root)
        self.transport_factory = transport_factory or (
            lambda config: MemberProbeTransport(config, state_root=self.state_root / 'ssh'))

    def _context(self, enrollment_id):
        with self.repository._session() as session:
            return self._context_in_session(session, enrollment_id)

    def _context_in_session(self, session, enrollment_id):
        row = session.get(EnrollmentRow, enrollment_id)
        if row is None or not row.used:
            raise EnrollmentUnavailable()
        record = EnrollmentRecord.model_validate(row.payload)
        if (record.enrollment_id != row.enrollment_id or record.owner_user_id != row.owner_user_id
                or record.code_hash != row.code_hash or record.registration_mode != 'resumable-v1'
                or record.revoked_at is not None or record.machine_id != record.invited_machine_id
                or record.member_admission_result is not None):
            raise EnrollmentUnavailable()
        owner = self.admissions.transport.enrollment._user(session, record.owner_user_id)
        token = session.get(MachineCredentialRow, record.exchange_credential_id)
        if UserRole.MACHINE_OWNER not in owner.roles or token is None or not token.active:
            raise EnrollmentUnavailable()
        credential = MachineAgentCredential.model_validate(token.payload)
        if (not credential.is_active() or credential.credential_id != token.credential_id
                or credential.token_hash != token.token_hash or token.machine_id != record.machine_id
                or credential.machine_id != record.machine_id):
            raise EnrollmentUnavailable()
        offer = checked_offer(record)
        validate_offer_scope(session, offer)
        consent = _stored_consent(record)
        claim = _root_claim(record)
        config_row = session.get(MachineExecutionConfigRow, record.machine_id)
        policy_row = session.get(PolicyRow, record.machine_id)
        if config_row is None or policy_row is None:
            raise ProbeUnavailable('member_probe_runtime_not_configured')
        selected_center_release().require_configured()
        config = MachineExecutionConfig.model_validate(config_row.payload)
        policy = MachinePolicy.model_validate(policy_row.payload)
        if (config.execution_provenance.get('member_bootstrap_stage') != 'acceptance'
                or config.execution_provenance.get('member_bootstrap_root_sha256') != canonical_digest(claim)):
            # An arbitrary old disabled execution configuration must not gain
            # new automatic SSH activity merely because this monitor exists.
            raise ProbeUnavailable('member_probe_bootstrap_handoff_required')
        if (config.machine_id != record.machine_id or config.enabled or not config.pinned_host_key
                or config.root_uuid != claim['root_uuid'] or config.remote_root != claim['remote_root']
                or config.runtime_version != selected_center_release().runtime_version
                or config.max_concurrent_units != 1 or config.target_concurrent_units != 1
                or policy.effective_mode() != MachineMode.PAUSED or policy.admin_mode_override is not None
                or policy.member_execution_limit is None or not policy.member_execution_limit.active
                or consent_policy_digest(policy) != consent['policy_sha256']):
            raise EnrollmentUnavailable()
        context = self.admissions.acceptance_context(session, record, config)
        return config, context

    def _unchanged(self, enrollment_id, context):
        config, current = self._context(enrollment_id)
        if canonical_digest(current) != canonical_digest(context):
            raise ProbeUnavailable('member_probe_context_changed')
        return config

    def _save(self, path, state, previous):
        raw = storage._json_bytes(state)
        storage._publish(path, raw, expected=previous)
        return raw

    def _run(self, state):
        run = self.repository.get_ssh_acceptance_run(state['run_id'])
        if run is None:
            raise ProbeUnavailable('member_probe_run_missing')
        checks = [c for c in run.checks if c.check_id == 'member_probe_context']
        if (run.status != AcceptanceStatus.RUNNING or run.worker_id != state['context']['machine_id'] or run.remote_root != state['remote_root']
                or len(checks) != 1 or canonical_digest(checks[0].evidence) != canonical_digest(state['context'])):
            raise ProbeUnavailable('member_probe_run_conflict')
        with self.repository._session() as session:
            latest = session.scalar(select(SshAcceptanceRow.run_id).where(
                SshAcceptanceRow.payload['worker_id'].as_string() == run.worker_id
            ).order_by(SshAcceptanceRow.created_at.desc(), SshAcceptanceRow.run_id.desc()).limit(1))
        if latest != run.run_id:
            raise ProbeUnavailable('member_probe_superseded_by_newer_acceptance')
        return run

    def _new(self, enrollment_id, config, context, path):
        with self.repository._session() as session:
            prior = session.scalar(select(SshAcceptanceRow.run_id).where(
                SshAcceptanceRow.payload['worker_id'].as_string() == config.machine_id).limit(1))
        if prior is not None:
            raise ProbeUnavailable('member_probe_existing_acceptance_requires_resume')
        run = SshAcceptanceRun(worker_id=config.machine_id, worker_hostname=config.expected_hostname or '',
            remote_root=config.remote_root, concurrency_levels=[1], status=AcceptanceStatus.RUNNING,
            checks=[
                AcceptanceCheck(check_id='member_probe_context', label='Fixed probe context',
                    status=AcceptanceStatus.RUNNING, evidence=context),
                AcceptanceCheck(check_id='member_admission_context', label='Center-owned member admission context',
                    status=AcceptanceStatus.PASSED, evidence=context),
            ])
        state = {'schema_version': 1, 'enrollment_id': enrollment_id, 'run_id': run.run_id,
            'remote_root': config.remote_root, 'context': context, 'run_created_at': run.created_at.isoformat(),
            'probes': {}}
        raw = self._save(path, state, None)  # Intent exists BEFORE any remote effect.
        self._claim_run(state,run)
        return state, raw

    def _claim_run(self,state,run):
        # Different controller processes may select different local work roots.
        # Serialize creation by enrollment in the DB as well as by local lock.
        def claim():
            with self.repository._session() as session,session.begin():
                self.admissions.transport.enrollment._lock(session,state['enrollment_id'])
                row=session.get(EnrollmentRow,state['enrollment_id'])
                record=EnrollmentRecord.model_validate(row.payload) if row is not None else None
                if record is None or record.revoked_at is not None or record.machine_id!=run.worker_id:
                    raise EnrollmentUnavailable()
                prior=session.scalar(select(SshAcceptanceRow).where(
                    SshAcceptanceRow.payload['worker_id'].as_string()==run.worker_id).limit(1))
                if prior is not None:
                    if prior.run_id!=run.run_id:
                        raise ProbeUnavailable('member_probe_existing_acceptance_requires_resume')
                    return
                session.add(SshAcceptanceRow(run_id=run.run_id,status=run.status.value,
                    created_at=run.created_at,payload=run.model_dump(mode='json')))
                self.admissions.transport.enrollment._audit(session,'member.fixed_probe_run_created',
                    'member-acceptance',state['enrollment_id'],machine_id=run.worker_id,run_id=run.run_id,
                    context_sha256=canonical_digest(state['context']),grants_execution=False)
        self.repository._retry_sqlite_write(claim)

    def _restore_missing_run(self, state):
        # Only a journal with NO prepared probe may finish a pre-DB creation crash.
        if state['probes'] or self.repository.get_ssh_acceptance_run(state['run_id']) is not None:
            return
        with self.repository._session() as session:
            prior = session.scalar(select(SshAcceptanceRow.run_id).where(
                SshAcceptanceRow.payload['worker_id'].as_string() == state['context']['machine_id']).limit(1))
        if prior is not None:
            raise ProbeUnavailable('member_probe_existing_acceptance_requires_resume')
        self._claim_run(state,SshAcceptanceRun(run_id=state['run_id'],
            worker_id=state['context']['machine_id'], remote_root=state['remote_root'], concurrency_levels=[1],
            status=AcceptanceStatus.RUNNING, created_at=_aware(state['run_created_at']),
            checks=[
                AcceptanceCheck(check_id='member_probe_context', label='Fixed probe context',
                    status=AcceptanceStatus.RUNNING, evidence=state['context']),
                AcceptanceCheck(check_id='member_admission_context', label='Center-owned member admission context',
                    status=AcceptanceStatus.PASSED, evidence=state['context']),
            ]))

    def _prepare(self, kind, state, directory, config):
        nonce = _sha((state['run_id'] + ':' + kind).encode())[:40]
        profile = SAFE_FAKE_TASK_V1 if kind == 'safe_fake_task' else PROJECT_WORKER_V1
        payload = ({'kind': 'rcn_safe_fake_task', 'acceptance_nonce': nonce} if kind == 'safe_fake_task'
            else {'kind': 'project-worker-v1', 'entrypoint': 'project_worker_smoke.py'})
        unit = WorkUnit(work_unit_id='up-' + nonce, ordinal=0, payload=payload,
            expected_duration_s=30, resources=ResourceRequest(cpus=1, memory_mb=256, disk_mb=16))
        job = JobEnvelope(job_id='jp-' + nonce, origin_submitter_id='member-acceptance',
            user_id='admin', project_id='compute-network-pilot', execution_profile_id=profile.profile_id,
            request_hash=canonical_digest({'kind': kind, 'context': state['context'], 'nonce': nonce}), work_units=[unit])
        external = 'ssh-member-probe-' + nonce
        assignment = Assignment(job_id=job.job_id, work_unit_id=unit.work_unit_id, machine_id=config.machine_id, scheduler='ssh')
        # Rebuilding before publication is safe; once journaled, these exact bytes
        # are frozen. The native staging API receives only this fixed task bundle.
        with tempfile.TemporaryDirectory(prefix='build-', dir=directory) as temporary:
            archive = Path(temporary) / 'probe.zip'
            common = dict(job=job, assignment=assignment, external_run_id=external, config=config,
                runtime_version=config.runtime_version, output_zip=archive)
            if kind == 'safe_fake_task':
                build_safe_fake_unit_bundle(**common)
            else:
                build_project_worker_unit_bundle(project_root=Path(__file__).parent/'acceptance_fixtures',
                    entrypoint='project_worker_smoke.py', project_files=[], arguments={'acceptance_nonce':nonce,'value':7}, **common)
            raw = archive.read_bytes()
        if len(raw) > 262144:
            raise ProbeUnavailable('member_probe_bundle_too_large')
        bundle_path = directory / (kind + '.zip')
        storage._check_private_file(bundle_path)
        if bundle_path.exists():
            # Crash before recording the hash: validate semantic identity rather
            # than replacing a ZIP that may carry different timestamp bytes.
            self._same_archive(storage._read_bytes(bundle_path, maximum=262144), raw)
        else:
            storage._publish(bundle_path, raw, maximum=262144)
        bundle_raw = storage._read_bytes(bundle_path, maximum=262144)
        with zipfile.ZipFile(bundle_path) as archive:
            request = json.loads(archive.read('request.json'))
        return {'external_run_id':external,'request':request,'bundle_sha256':_sha(bundle_raw),
            'nonce':nonce,'phase':'prepared','evidence':None}

    @staticmethod
    def _same_archive(actual, expected):
        def contents(raw):
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                infos = archive.infolist()
                if len(infos)>8 or len({i.filename for i in infos})!=len(infos) or sum(i.file_size for i in infos)>262144:
                    raise ProbeUnavailable('member_probe_bundle_invalid')
                return {i.filename:archive.read(i) for i in infos}
        if contents(actual)!=contents(expected):
            raise ProbeUnavailable('member_probe_unowned_bundle')

    def _validate_probe(self, kind, state, probe, directory):
        if set(probe) != {'external_run_id','request','bundle_sha256','nonce','phase','evidence'}:
            raise ProbeUnavailable('member_probe_journal_invalid')
        nonce = _sha((state['run_id']+':'+kind).encode())[:40]
        profile = SAFE_FAKE_TASK_V1 if kind=='safe_fake_task' else PROJECT_WORKER_V1
        request = probe['request']
        expected = {'external_run_id':'ssh-member-probe-'+nonce, 'machine_id':state['context']['machine_id'],
            'job_id':'jp-'+nonce,'work_unit_id':'up-'+nonce,
            'runtime_version':state['context']['runtime_version'],'profile_id':profile.profile_id}
        if (probe['nonce']!=nonce or probe['external_run_id']!=expected['external_run_id']
                or any(request.get(k)!=v for k,v in expected.items())
                or probe['phase'] not in {'prepared','submitted','collecting','passed'}):
            raise ProbeUnavailable('member_probe_journal_invalid')
        bundle = directory/(kind+'.zip')
        storage._check_private_file(bundle)
        raw = storage._read_bytes(bundle, maximum=262144)
        if _sha(raw)!=probe['bundle_sha256']:
            raise ProbeUnavailable('member_probe_bundle_changed')
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if storage._json_bytes(json.loads(archive.read('request.json')))!=storage._json_bytes(request):
                raise ProbeUnavailable('member_probe_request_changed')
        return bundle

    def _record(self, state, probe, remote_state, *, evidence=None):
        request = probe['request']
        existing = self.repository.get_remote_run(probe['external_run_id'])
        expected = {name: request[name] for name in ('machine_id','job_id','work_unit_id','request_hash')}
        if existing is not None and any(getattr(existing,k) != v for k,v in expected.items()):
            raise ProbeUnavailable('member_probe_remote_ledger_conflict')
        self.repository.put_remote_run(RemoteRunRecord(external_run_id=probe['external_run_id'], **expected,
            state=remote_state, remote_relative_path=(evidence or {}).get('remote_relative_path',''),
            artifacts_available=remote_state=='completed'))
        run = self._run(state)
        if probe['external_run_id'] not in run.external_run_ids:
            run.external_run_ids.append(probe['external_run_id'])
            self.repository.put_ssh_acceptance_run(run)

    @staticmethod
    def _validate_status(probe, status):
        if status == {'external_run_id':probe['external_run_id'], 'state':'staged','message':'status not published yet'}:
            return False
        if (not isinstance(status,dict) or type(status.get('schema_version')) is not int or status['schema_version'] != 1
                or status.get('state') not in {s.value for s in RemoteRunState}
                or any(status.get(k) != probe['request'][k] for k in ('external_run_id','machine_id','job_id','work_unit_id','request_hash'))):
            raise ProbeUnavailable('member_probe_status_identity_mismatch')
        age = (datetime.now(timezone.utc) - _aware(status.get('updated_at'))).total_seconds()
        if age < -5 or (status['state'] not in TERMINAL and age > 45):
            raise ProbeUnavailable('member_probe_status_stale')
        return True

    def _collect(self, kind, probe, transport, directory):
        # A failed collection never changes the execution identity. Only these
        # temporary, local nonscientific verification copies are discarded.
        with tempfile.TemporaryDirectory(prefix='collect-', dir=directory) as temp:
            destination = Path(temp) / 'output'
            transport.download_outputs(probe['external_run_id'], destination)
            files = [p for p in destination.rglob('*') if p.is_file()]
            if len(files) > 32 or sum(p.stat().st_size for p in files) > 4*1024*1024:
                raise ProbeUnavailable('member_probe_output_exceeds_bound')
            for p in destination.rglob('*'):
                storage._unlinked(p)
            manifests = list(destination.rglob('artifact-manifest.json'))
            if len(manifests) != 1:
                raise ProbeUnavailable('member_probe_manifest_missing')
            manifest = storage._json_document(storage._read_bytes(manifests[0]))
            if any(manifest.get(k) != probe['request'][k] for k in ('external_run_id','job_id','work_unit_id')):
                raise ProbeUnavailable('member_probe_manifest_identity_mismatch')
            entries = manifest.get('files')
            if not isinstance(entries,list) or not entries or len(entries)>16:
                raise ProbeUnavailable('member_probe_manifest_invalid')
            checked = {}
            for entry in entries:
                relative = PurePosixPath(entry['relative_path'])
                if relative.is_absolute() or '..' in relative.parts or '\\' in str(relative) or ':' in str(relative):
                    raise ProbeUnavailable('member_probe_manifest_path_invalid')
                path = manifests[0].parent / Path(*relative.parts)
                storage._unlinked(path)
                if (entry['relative_path'] in checked or not path.is_file() or type(entry['size_bytes']) is not int
                        or path.stat().st_size != entry['size_bytes'] or _sha(path.read_bytes()) != entry['sha256']):
                    raise ProbeUnavailable('member_probe_output_hash_mismatch')
                checked[entry['relative_path']] = path
            name = 'safe-fake-result.json' if kind == 'safe_fake_task' else 'result.json'
            if name not in checked:
                raise ProbeUnavailable('member_probe_result_missing')
            result = storage._json_document(storage._read_bytes(checked[name]))
            valid = result.get('acceptance_nonce') == probe['nonce']
            if kind == 'safe_fake_task':
                valid = valid and result.get('profile_id') == SAFE_FAKE_TASK_V1.profile_id and result.get('message') == 'fixed safe fake task completed; no user command was executed'
            else:
                valid = valid and result.get('value') == 7 and result.get('message') == 'project worker executed without a shell'
            if not valid:
                raise ProbeUnavailable('member_probe_result_mismatch')
            return {'external_run_id':probe['external_run_id'],'request_sha256':probe['request']['request_hash'],
                'bundle_sha256':probe['bundle_sha256'],'result_hash_verified':True,'fixed_profile':probe['request']['profile_id'],
                'result_sha256':_sha(checked[name].read_bytes()),'artifact_count':len(checked),'terminal_state':'completed'}

    def _verify_runtime(self, enrollment_id, state, config, run, transport):
        """One read-only inventory observation; the final evidence write is atomic."""
        from .member_runtime_verification import RuntimeVerificationUnavailable
        verifier=self.runtime_verifier
        expected=verifier.expected_evidence(config)
        checks=[c for c in run.checks if c.check_id=='runtime_deployed']
        if len(checks)>1:
            raise ProbeUnavailable('member_runtime_check_conflict')
        if checks:
            prior=checks[0]
            evidence=prior.evidence
            if (prior.status not in {AcceptanceStatus.PASSED,AcceptanceStatus.RUNNING}
                    or not isinstance(evidence,dict) or set(evidence)!=set(expected)|{'verified_at'}
                    or canonical_digest({k:v for k,v in evidence.items() if k!='verified_at'})!=canonical_digest(expected)):
                raise ProbeUnavailable('member_runtime_check_conflict')
            if prior.status==AcceptanceStatus.RUNNING:
                if evidence['verified_at'] is not None:
                    raise ProbeUnavailable('member_runtime_check_conflict')
            else:
                age=(datetime.now(timezone.utc)-_aware(evidence['verified_at'])).total_seconds()
                if 0<=age<=60:
                    return {'state':'runtime_inventory_verified','run_id':run.run_id,
                            'check_id':'runtime_deployed','grants_execution':False,'remaining':'full machine acceptance'}
        original=canonical_digest(run.model_dump(mode='json'))
        error=None
        try:
            evidence=verifier.verify(config,transport)
        except RuntimeVerificationUnavailable as exc:
            error=exc
            evidence={**expected,'verified_at':None}
        def write():
            with self.repository._session() as session,session.begin():
                self.admissions.transport.enrollment._lock(session,enrollment_id)
                _,current=self._context_in_session(session,enrollment_id)
                if canonical_digest(current)!=canonical_digest(state['context']):
                    raise ProbeUnavailable('member_probe_context_changed')
                row=session.get(SshAcceptanceRow,run.run_id)
                latest=session.scalar(select(SshAcceptanceRow.run_id).where(
                    SshAcceptanceRow.payload['worker_id'].as_string()==config.machine_id
                ).order_by(SshAcceptanceRow.created_at.desc(),SshAcceptanceRow.run_id.desc()).limit(1))
                if row is None or latest!=run.run_id or row.status!='running' or canonical_digest(row.payload)!=original:
                    raise ProbeUnavailable('member_runtime_check_run_changed')
                updated=SshAcceptanceRun.model_validate(row.payload)
                updated.checks=[c for c in updated.checks if c.check_id!='runtime_deployed']
                updated.checks.append(AcceptanceCheck(check_id='runtime_deployed',label='Read-only approved runtime inventory',
                    status=AcceptanceStatus.RUNNING if error else AcceptanceStatus.PASSED,evidence=evidence))
                if error is None:
                    derived={
                        'root_initialized': AcceptanceCheck(check_id='root_initialized', label='Signed managed root reverified through runtime inventory',
                            status=AcceptanceStatus.PASSED, evidence={'verification_kind':'runtime-root-revalidation-v1',
                                'remote_root':config.remote_root,'root_uuid':config.root_uuid,'verified_at':evidence['verified_at'],
                                'execution_config_sha256':evidence['execution_config_sha256']}),
                        'ssh_transport': AcceptanceCheck(check_id='ssh_transport', label='Pinned authenticated SSH used for runtime inventory',
                            status=AcceptanceStatus.PASSED, evidence={'verification_kind':'pinned-ssh-runtime-read-v1',
                                'verified_at':evidence['verified_at'],'execution_config_sha256':evidence['execution_config_sha256'],
                                'pinned_host_key_sha256':_sha(config.pinned_host_key.encode('utf-8'))}),
                    }
                    for check_id,check in derived.items():
                        found=[c for c in updated.checks if c.check_id==check_id]
                        if len(found)>1 or (found and found[0].status!=AcceptanceStatus.PASSED):
                            raise ProbeUnavailable('member_bootstrap_check_conflict')
                        if not found:updated.checks.append(check)
                updated.updated_at=datetime.now(timezone.utc)
                row.payload=updated.model_dump(mode='json')
                self.admissions.transport.enrollment._audit(session,
                    'member.runtime_inventory_unconfirmed' if error else 'member.runtime_inventory_verified',
                    'member-acceptance',enrollment_id,machine_id=config.machine_id,run_id=run.run_id,
                    inventory_sha256=evidence['inventory_sha256'],file_count=evidence['file_count'],grants_execution=False)
        self.repository._retry_sqlite_write(write)
        if error:
            raise ProbeUnavailable('member_runtime_verification_unconfirmed') from None
        return {'state':'runtime_inventory_verified','run_id':run.run_id,'check_id':'runtime_deployed',
                'grants_execution':False,'remaining':'full machine acceptance'}

    def _verify_channels(self, enrollment_id, state, config):
        from .member_channel_verification import evaluate_channels, KIND
        from .repository import MachineOperationalStatusRow
        def write():
            with self.repository._session() as session,session.begin():
                self.admissions.transport.enrollment._lock(session,enrollment_id)
                _,current=self._context_in_session(session,enrollment_id)
                if canonical_digest(current)!=canonical_digest(state['context']):
                    raise ProbeUnavailable('member_probe_context_changed')
                record=EnrollmentRecord.model_validate(session.get(EnrollmentRow,enrollment_id).payload)
                row=session.get(SshAcceptanceRow,state['run_id'])
                latest=session.scalar(select(SshAcceptanceRow.run_id).where(
                    SshAcceptanceRow.payload['worker_id'].as_string()==config.machine_id
                ).order_by(SshAcceptanceRow.created_at.desc(),SshAcceptanceRow.run_id.desc()).limit(1))
                if row is None or latest!=state['run_id'] or row.status!='running':
                    raise ProbeUnavailable('member_channel_acceptance_changed')
                run=SshAcceptanceRun.model_validate(row.payload)
                operational=session.get(MachineOperationalStatusRow,config.machine_id)
                evidence=evaluate_channels(config,operational.payload if operational else None,
                    registration_origin=record.registration_url)
                existing=[c for c in run.checks if c.check_id=='independent_heartbeat']
                if len(existing)>1 or (existing and existing[0].evidence.get('verification_kind')!=KIND):
                    raise ProbeUnavailable('member_channel_check_conflict')
                status=AcceptanceStatus.PASSED if evidence['passed'] else AcceptanceStatus.RUNNING
                if existing and existing[0].status==status and canonical_digest(existing[0].evidence)==canonical_digest(evidence):
                    return evidence['state']
                run.checks=[c for c in run.checks if c.check_id!='independent_heartbeat']
                run.checks.append(AcceptanceCheck(check_id='independent_heartbeat',label='Independent authenticated channel observations',
                    status=status,evidence=evidence))
                run.updated_at=datetime.now(timezone.utc);row.payload=run.model_dump(mode='json')
                self.admissions.transport.enrollment._audit(session,'member.channel_acceptance_observed','member-acceptance',
                    enrollment_id,machine_id=config.machine_id,run_id=run.run_id,state=evidence['state'],grants_execution=False)
                return evidence['state']
        return self.repository._retry_sqlite_write(write)

    def tick(self, enrollment_id):
        """One prepared/submit/poll/collect step. Never wait for an entire job."""
        from .member_enrollment import ID_PATTERN
        import re
        if not re.fullmatch(ID_PATTERN, enrollment_id):
            raise ProbeUnavailable('invalid_member_probe_identity')
        config, context = self._context(enrollment_id)
        directory = self.state_root / enrollment_id
        storage._private_directory(directory)
        with storage._exclusive(directory):
            path = directory / JOURNAL
            storage._check_private_file(path)
            raw = storage._read_bytes(path) if path.exists() else None
            if raw is None:
                state, raw = self._new(enrollment_id,config,context,path)
            else:
                state = storage._json_document(raw)
                if (set(state) != {'schema_version','enrollment_id','run_id','remote_root','context','run_created_at','probes'}
                        or type(state['schema_version']) is not int or state['schema_version'] != 1
                        or state['enrollment_id'] != enrollment_id or canonical_digest(state['context']) != canonical_digest(context)
                        or state['remote_root'] != config.remote_root or not set(state['probes']).issubset(KINDS)):
                    raise ProbeUnavailable('member_probe_journal_conflict')
                self._restore_missing_run(state)
            run = self._run(state)
            transport = self.transport_factory(config)
            live = transport.read_supervisor_status()
            own = {v['external_run_id'] for v in state['probes'].values()}
            if (live.get('machine_id') != config.machine_id or live.get('root_uuid') != config.root_uuid
                    or live.get('runtime_version') != config.runtime_version or type(live.get('max_concurrent_units')) is not int
                    or live['max_concurrent_units'] != 1 or not isinstance(live.get('active_run_ids'),list)
                    or not set(live['active_run_ids']).issubset(own)
                    or not 0 <= (datetime.now(timezone.utc)-_aware(live.get('updated_at'))).total_seconds() <= 45):
                raise ProbeUnavailable('member_probe_supervisor_not_ready')
            with self.repository._session() as session:
                for remote in session.scalars(select(RemoteRunRow).where(RemoteRunRow.machine_id==config.machine_id)):
                    if remote.external_run_id not in own and remote.state not in TERMINAL:
                        raise ProbeUnavailable('member_probe_other_work_requires_reconciliation')
            for kind in KINDS:
                probe = state['probes'].get(kind)
                if probe is not None:
                    self._validate_probe(kind,state,probe,directory)
                    if probe['phase']=='passed':
                        matches=[c for c in run.checks if c.check_id==kind]
                        remote=self.repository.get_remote_run(probe['external_run_id'])
                        if (len(matches)!=1 or matches[0].status!=AcceptanceStatus.PASSED
                                or canonical_digest(matches[0].evidence)!=canonical_digest(probe['evidence'])
                                or remote is None or remote.state!=RemoteRunState.COMPLETED
                                or remote.request_hash!=probe['request']['request_hash']):
                            raise ProbeUnavailable('member_probe_completed_evidence_changed')
                        continue
                if probe is None:
                    probe = self._prepare(kind,state,directory,config)
                    state['probes'][kind] = probe
                    raw = self._save(path,state,raw)
                bundle = self._validate_probe(kind,state,probe,directory)
                self._unchanged(enrollment_id,context)
                self._record(state,probe,'staged' if probe['phase']=='prepared' else 'uncertain')
                status = transport.read_status(probe['external_run_id'])
                exists = self._validate_status(probe,status)
                if not exists:
                    # Same frozen bundle/external ID only. Worker idempotency handles
                    # a lost prior upload response; no alternate request is minted.
                    transport.stage_bundle(probe['external_run_id'],bundle)
                    self._unchanged(enrollment_id,context)
                    probe['phase']='submitted';self._save(path,state,raw)
                    return {'state':'probe_submitted','run_id':run.run_id,'check_id':kind,'grants_execution':False}
                self._record(state,probe,'collecting' if status['state']=='completed' else status['state'],evidence=status)
                if status['state'] not in TERMINAL:
                    return {'state':'probe_running','run_id':run.run_id,'check_id':kind,'grants_execution':False}
                if status['state'] != 'completed':
                    raise ProbeUnavailable('member_probe_execution_failed_requires_review')
                evidence = self._collect(kind,probe,transport,directory)
                self._unchanged(enrollment_id,context)
                self._record(state,probe,'completed',evidence=status)
                run = self._run(state)
                if any(c.check_id==kind for c in run.checks):
                    previous = next(c for c in run.checks if c.check_id==kind)
                    if previous.status != AcceptanceStatus.PASSED or canonical_digest(previous.evidence) != canonical_digest(evidence):
                        raise ProbeUnavailable('member_probe_check_changed')
                else:
                    run.checks.append(AcceptanceCheck(check_id=kind,label='Real fixed-profile execution',
                        status=AcceptanceStatus.PASSED,evidence=evidence))
                    self.repository.put_ssh_acceptance_run(run)
                probe.update(phase='passed',evidence=evidence);self._save(path,state,raw)
                return {'state':'probe_verified','run_id':run.run_id,'check_id':kind,'grants_execution':False}
            if self.runtime_verifier is not None:
                result=self._verify_runtime(enrollment_id,state,config,run,transport)
                result['channel_state']=self._verify_channels(enrollment_id,state,config)
                return result
            return {'state':'fixed_probes_verified','run_id':run.run_id,'grants_execution':False,
                'remaining':'runtime-installation, COMSOL/cancellation, heartbeat/reboot and tunnel acceptance'}
