"""Bounded automatic finalization of existing center-owned machine evidence.

An optional producer advances one genuine packaged fixed-profile probe per tick.
It never supplies COMSOL/reboot/cancellation evidence. Finalization still requires
the complete center-owned acceptance run; partial evidence remains pending.
"""
from __future__ import annotations

import asyncio
from datetime import datetime,timezone
import logging
import threading

from sqlalchemy import select

from .member_admission import MemberAdmissions
from .member_enrollment import EnrollmentUnavailable
from .repository import EnrollmentRow,SshAcceptanceRow

INTERVAL_SECONDS=15
BATCH_SIZE=8


class MemberAdmissionMonitor:
    def __init__(self,repository,*,verification_root,probe_runner=None,scientific_producer=None):
        self.repository=repository
        self.admissions=MemberAdmissions(repository,verification_root=verification_root)
        self.cursor=''
        self.probe_runner=probe_runner
        self.scientific_producer=scientific_producer
        self.probe_cursor=''
        self.audit_cursor=''
        self.audit_lock=threading.Lock()
        self.independent_audits=False
        self.audit_status={}
        self.lock=threading.Lock()
        self.status={'state':'not_started','last_checked_at':None,'reviewed':0,'admitted':0,'pending':0}

    def tick(self) -> dict:
        if not self.lock.acquire(blocking=False):
            return {**self.status,'state':'already_running'}
        try:
            with self.repository._session() as session:
                query=select(EnrollmentRow).where(
                    EnrollmentRow.payload['member_compute_consent']['consent_sha256'].as_string().is_not(None),
                    EnrollmentRow.payload['conditional_admission_offer']['offer_sha256'].as_string().is_not(None),
                    EnrollmentRow.payload['member_admission_result']['state'].as_string().is_(None))
                candidates=list(session.scalars(query.where(EnrollmentRow.enrollment_id>self.cursor)
                    .order_by(EnrollmentRow.enrollment_id).limit(BATCH_SIZE)))
                if not candidates and self.cursor:
                    self.cursor=''
                    candidates=list(session.scalars(query.order_by(EnrollmentRow.enrollment_id).limit(BATCH_SIZE)))
                identities=[(row.enrollment_id,row.payload.get('machine_id')) for row in candidates]
                probe_identity=None
                if self.probe_runner is not None:
                    probe_query=query.with_only_columns(EnrollmentRow.enrollment_id)
                    probe_identity=session.scalar(probe_query.where(EnrollmentRow.enrollment_id>self.probe_cursor)
                        .order_by(EnrollmentRow.enrollment_id).limit(1))
                    if probe_identity is None and self.probe_cursor:
                        self.probe_cursor=''
                        probe_identity=session.scalar(probe_query.order_by(EnrollmentRow.enrollment_id).limit(1))
            # Ready trust-first members are admitted before an optional probe
            # can fail on an unavailable scientific adapter. Historical offers
            # retain their original full-acceptance finalization contract.
            early_admitted=set()
            early_ids=list(dict.fromkeys([identity for identity,_ in identities]+([probe_identity] if probe_identity else [])))
            for identity in early_ids:
                with self.repository._session() as session:
                    row=session.get(EnrollmentRow,identity)
                    offer=(row.payload.get('conditional_admission_offer') or {}) if row else {}
                    mode=(offer.get('scope') or {}).get('admission_policy')
                if mode!='trust_first':
                    continue
                try:
                    if self.admissions.finalize(identity).get('state')=='admitted':
                        early_admitted.add(identity)
                except EnrollmentUnavailable:
                    pass
            probe_result=None
            if probe_identity is not None and probe_identity not in early_admitted:
                # A separate keyset cursor is essential: using a global numeric
                # offset inside rotating batches can starve half the members.
                self.probe_cursor=probe_identity
                try:
                    probe_result=self.probe_runner.tick(probe_identity)
                except EnrollmentUnavailable:
                    probe_result={'state':'pending_authority'}
                except Exception as exc:
                    from .member_fixed_probes import ProbeUnavailable
                    # No raw SSH/HTTP exceptions, secrets or remote paths in logs.
                    code=str(exc) if isinstance(exc,ProbeUnavailable) else 'member_probe_temporarily_unavailable'
                    probe_result={'state':'pending','reason_code':code}
            reviewed=admitted=pending=0
            for enrollment_id,machine_id in identities:
                reviewed+=1;self.cursor=enrollment_id
                if enrollment_id in early_admitted:
                    admitted+=1;continue
                # A JSON identity filter avoids full history reads. A later failed
                # run must not cause an older passing run to be silently selected.
                with self.repository._session() as session:
                    row=session.scalar(select(SshAcceptanceRow).where(
                        SshAcceptanceRow.payload['worker_id'].as_string()==machine_id
                    ).order_by(SshAcceptanceRow.created_at.desc(),SshAcceptanceRow.run_id.desc()).limit(1))
                    run_id=row.run_id if row is not None else None
                if run_id is None:
                    pending+=1;continue
                try:
                    result=self.admissions.finalize(enrollment_id,run_id)
                    admitted+=int(result.get('state')=='admitted')
                except EnrollmentUnavailable:
                    pending+=1
            self.status={'state':'active','last_checked_at':datetime.now(timezone.utc).isoformat(),
                'reviewed':reviewed,'admitted':admitted,'pending':pending}
            if not self.independent_audits:
                self.tick_audits()
            self.status.update(self.audit_status)
            if probe_result is not None:
                self.status['fixed_probe']=probe_result
            return dict(self.status)
        finally:
            self.lock.release()

    def tick_audits(self) -> dict:
        # Production runs this independently of slow pre-admission SSH probes.
        # Evidence generation precedes consumption; both recover from DB state.
        if not self.audit_lock.acquire(blocking=False):
            return dict(self.audit_status)
        try:
            result={}
            if self.scientific_producer is not None:
                try:
                    result['scientific']=self.scientific_producer.tick()
                except Exception as exc:
                    result['scientific']={'state':'blocked','reason_code':'scientific_acceptance_iteration_failed',
                                          'error_type':type(exc).__name__}
            result['audit']=self._audit_tick()
            self.audit_status=result
            return dict(result)
        finally:
            self.audit_lock.release()

    def _audit_tick(self) -> dict:
        from .member_async_audit import reconcile_member_audit
        with self.repository._session() as session:
            query=select(EnrollmentRow.enrollment_id).where(
                EnrollmentRow.payload['member_admission_result']['state'].as_string()=='admitted',
                EnrollmentRow.payload['member_admission_result']['admission_policy'].as_string()=='trust_first')
            identities=list(session.scalars(query.where(EnrollmentRow.enrollment_id>self.audit_cursor)
                .order_by(EnrollmentRow.enrollment_id).limit(BATCH_SIZE)))
            if not identities and self.audit_cursor:
                self.audit_cursor=''
                identities=list(session.scalars(query.order_by(EnrollmentRow.enrollment_id).limit(BATCH_SIZE)))
        result={'reviewed':0,'passed':0,'failed':0,'pending':0}
        for identity in identities:
            self.audit_cursor=identity;result['reviewed']+=1
            try:
                state=reconcile_member_audit(self.admissions,identity).get('state')
            except Exception:
                # One malformed or unavailable report cannot starve other members.
                state='pending'
            if state in result:
                result[state]+=1
        return result


def install_member_admission_monitor(app,*,repository,verification_root,dataset_mode,service=None,state_root=None):
    if dataset_mode!='formal':
        return
    producer=None
    if service is not None:
        from pathlib import Path
        from .member_fixed_probes import MemberFixedProbeRunner
        import os
        verifier=None
        selected=os.environ.get('RCN_MEMBER_APPROVED_RUNTIME_ARCHIVE')
        release_descriptor=None
        if os.environ.get('RCN_RUNTIME_DESCRIPTOR'):
            from .member_release_catalog import selected_center_release
            release_descriptor=selected_center_release()
            if not selected:
                selected=str(release_descriptor.archive_path)
        if selected:
            from .member_runtime_verification import MemberRuntimeVerifier
            if not Path(selected).is_absolute():
                raise ValueError('member runtime archive must be explicitly absolute')
            verifier=MemberRuntimeVerifier(Path(selected), release_descriptor=release_descriptor)
        producer=MemberFixedProbeRunner(service,verification_root=verification_root,
            state_root=Path(verification_root).parent/'fixed-member-probes',runtime_verifier=verifier)
    scientific=None
    # Origin-owned scientific probes require a separate adapter; no bundled science.
    monitor=MemberAdmissionMonitor(repository,verification_root=verification_root,probe_runner=producer,
                                   scientific_producer=scientific)
    app.state.member_admission_monitor=monitor
    monitor.independent_audits=scientific is not None

    async def watch(iteration):
        while True:
            work=asyncio.create_task(asyncio.to_thread(iteration))
            try:
                # Shield the single bounded iteration so shutdown can JOIN it;
                # never dispose the DB while a cancelled background thread writes.
                await asyncio.shield(work)
            except asyncio.CancelledError:
                try:
                    await work
                except Exception:
                    logging.getLogger(__name__).error('member admission iteration failed during shutdown')
                raise
            except Exception:
                monitor.status={**monitor.status,'state':'degraded','reason_code':'admission_reconciliation_failed'}
                logging.getLogger(__name__).error('member admission reconciliation failed; no success claimed')
            await asyncio.sleep(INTERVAL_SECONDS)

    @app.on_event('startup')
    async def start_member_admission_monitor():
        task=getattr(app.state,'member_admission_monitor_task',None)
        if task is None or task.done():
            app.state.member_admission_monitor_task=asyncio.create_task(watch(monitor.tick))
        if monitor.independent_audits:
            task=getattr(app.state,'member_audit_monitor_task',None)
            if task is None or task.done():
                app.state.member_audit_monitor_task=asyncio.create_task(watch(monitor.tick_audits))

    @app.on_event('shutdown')
    async def stop_member_admission_monitor():
        tasks=[getattr(app.state,name,None) for name in ('member_admission_monitor_task','member_audit_monitor_task')]
        for task in tasks:
            if task is not None:task.cancel()
        for task in tasks:
            if task is not None:
                try:await task
                except asyncio.CancelledError:pass
