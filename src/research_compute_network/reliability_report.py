"""Bounded secret-free operator report. Reads existing metadata only."""
from collections import Counter
from datetime import datetime,timezone
from .failure_policy import failure_advice
from .release_identity import current_build
from .scheduling_controls import describe


def distribution_contract():
    return {'schema_version':1,'kind':'member-distribution-contract','public_installer_contains_invitation':False,
        'supported_invitation_schemas':[1,2],'personal_token_is_machine_credential':False,
        'initial_worker_state':'zero_capacity_pending_identity_and_consent',
        'admission_policies':{'new_explicit_compute_offer':'trust_first_async_scientific_audit',
                              'legacy_or_missing_policy':'acceptance_required'},
        'roles':{'view_and_submit':'member_plus_project_grant','contribute':'machine_owner_plus_explicit_consent'},
        'update_boundaries':{'web':'coordinator_release_then_browser_refresh',
                             'member_client':'verified_installer_preserve_identity',
                             'worker':'separate_approved_sealed_runtime_no_automatic_rollout'},
        'required_verifications':['public_package_hash','independent_personal_identity','project_scope',
            'protected_private_invitation','pinned_transport_identity','runtime_and_owner_budget'],
        'organization_code_signed':False,'protocol_version':1}


def report(repository):
    from .cluster_insights import read_jobs
    now=datetime.now(timezone.utc)
    jobs,source=read_jobs(repository,now=now,max_jobs=200)
    failures=[];states=Counter();machine_counts=Counter()
    for job in jobs:
        for unit in job.get('work_units') or []:
            states[unit.get('status','unknown')]+=1
            attempts=unit.get('attempts') or []
            if not attempts:continue
            a=attempts[-1]
            if a.get('state') in {'failed','uncertain','reconcile_pending','cancel_pending'}:
                machine_counts[a.get('machine_id') or 'unknown']+=1
                if len(failures)<50:
                    advice=failure_advice(a.get('failure_reason') or unit.get('failure_reason'),reported_class=a.get('failure_class'))
                    # Operator export deliberately omits raw excerpts even after
                    # sanitization; share it without science, paths or secrets.
                    advice.pop('evidence_excerpt',None)
                    failures.append({'job_id':job.get('job_id'),'work_unit_id':unit.get('work_unit_id'),
                        'attempt_id':a.get('attempt_id'),'machine_id':a.get('machine_id'),
                        'state':a.get('state'),'advice':advice})
    status=repository.get_dispatcher_status()
    return {'schema_version':1,'observed_at':now.isoformat(),'build':current_build(),
        'scheduling':describe(repository.get_feature_settings()),'source':source,
        'dispatcher':{'phase':str(status.phase),'desired_state':status.desired_state,
            'accepting_assignments':status.accepting_assignments,'pending_reconciliation':status.pending_reconciliation,
            'io_snapshot':status.io_snapshot,'last_successful_cycle_at':status.last_successful_cycle_at.isoformat() if status.last_successful_cycle_at else None},
        'unit_states':dict(states),'machine_recovery_counts':dict(machine_counts),'recovery_items':failures,
        'recovery_items_truncated':sum(machine_counts.values())>len(failures),
        'privacy':{'credentials':False,'scientific_payloads':False,'host_paths':False,'raw_error_text':False},
        'performs_remote_io':False,'performs_mutations':False}
