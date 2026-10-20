"""Conservative center-only failure advice and repeat-OOM placement guard.

Original remote text remains the evidence. Advice is not a scientific verdict,
permission to change a solver, proof that a timed-out run died, or a new retry.
"""
from __future__ import annotations
from .failure_diagnostics import (is_memory_exhaustion_failure,is_comsol_disconnect_failure,
    is_storage_exhaustion_failure,is_ssh_transport_failure,is_collection_integrity_failure,
    is_deterministic_scientific_failure,sanitize_failure_text)


def failure_advice(message, *, reported_class=None):
    text=str(message or '')
    cleanup=is_comsol_disconnect_failure(text)
    if is_collection_integrity_failure(text):
        kind,scope,action='integrity','artifact','retain_evidence_and_review'
    elif is_memory_exhaustion_failure(text):
        kind,scope,action='memory_exhaustion','machine_and_job','require_changed_resource_conditions'
    elif is_storage_exhaustion_failure(text):
        kind,scope,action='storage_exhaustion','machine_volume','wait_for_verified_storage_recovery'
    elif is_deterministic_scientific_failure(text):
        kind,scope,action='scientific_input','job','origin_review_no_automatic_science_change'
    elif cleanup:
        kind,scope,action='comsol_lifecycle_unknown','attempt','inspect_primary_error_before_retry'
    elif any(marker in text.lower() for marker in ('host key verification failed','permission denied (publickey',
                                                  'unprotected private key file','private key will be ignored')):
        kind,scope,action='transport_identity','machine_identity','operator_identity_repair_no_automatic_acl_change'
    elif is_ssh_transport_failure(text):
        kind,scope,action='transport','machine','observe_original_execution_with_backoff'
    else:
        kind,scope,action='unknown','attempt','retain_original_attempt_and_review'
    return {'schema_version':1,'classification_version':'center-evidence-v1','kind':kind,
        'scope':scope,'next_action':action,'reported_class':str(reported_class) if reported_class else None,
        'cleanup_error_present':cleanup,'primary_error_available':bool(text),
        'changes_scientific_inputs':False,'permits_automatic_recompute':False,
        'evidence_excerpt':sanitize_failure_text(text,max_length=500)}


def memory_retry_blocker(job,unit,machine,policy,execution_config):
    """A positive same-Job/machine OOM blocks unchanged resource conditions.

    This is a placement check shared with diagnostics, not another background
    dispatcher. It cannot rewrite failed Attempts. A lower, acknowledged target
    or a genuinely larger reservation may allow the existing bounded retry.
    Ordinary live RAM/disk/CPU and all other placement gates still apply.
    """
    target=min(policy.max_concurrent_units,
        execution_config.target_concurrent_units if execution_config else policy.max_concurrent_units)
    requested=(unit.resolved_resources.resources.memory_mb if unit.resolved_resources else unit.resources.memory_mb)
    candidates=[]
    for source in job.work_units:
        # A successful retry closes this Unit's old failure; do not hold a job
        # forever on historical OOM records whose recovery was already proved.
        if not source.attempts:continue
        failed=source.attempts[-1]
        if (failed.machine_id!=machine.machine_id or failed.state!='failed'
                or str(failed.failure_class)!='resource_exhaustion'
                or failed.execution_completed or failed.collected_at
                or not is_memory_exhaustion_failure(failed.failure_reason or source.failure_reason or '')):
            continue
        frozen=failed.resolved_resources
        old_memory=frozen.resources.memory_mb if frozen else None
        old_capacity=failed.effective_capacity
        larger=old_memory is not None and requested>old_memory
        reduced=old_capacity is not None and old_capacity>0 and target<old_capacity
        if not larger and not reduced:
            candidates.append({'attempt_id':failed.attempt_id,'failed_memory_mb':old_memory,
                'failed_effective_capacity':old_capacity,'requested_memory_mb':requested,'current_target':target})
    if not candidates:return None
    return {'reason_code':'memory_failure_conditions_unchanged',
            'scope':'machine_and_job','blocked_attempt_count':len(candidates),
            'evidence':candidates[:8],'next_action':'increase_bound_memory_or_reduce_target_then_recheck'}
