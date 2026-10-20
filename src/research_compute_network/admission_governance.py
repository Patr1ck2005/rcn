"""Control-plane admission governance; no scientific or worker-wire changes."""
from __future__ import annotations

from datetime import datetime, timezone

from .connection_health import fresh
from .member_admission_contract import canonical_digest
from .runtime_policy import STABLE_RUNTIME_VERSION


TRUST_FIRST = 'trust_first'
ACCEPTANCE_REQUIRED = 'acceptance_required'


def offer_governance(offer: dict) -> str:
    # A missing field belongs to a historical signed offer, not today's default.
    return offer['scope'].get('admission_policy', ACCEPTANCE_REQUIRED)


def trust_first_execution(config) -> bool:
    return config is not None and config.execution_provenance.get('admission_policy') == TRUST_FIRST


def consent_policy_digest(policy) -> str:
    # Preserve the signed shape of policies serialized before shared-host fields.
    # Explicit fields, including defaults, remain part of every new signature.
    absent = {'shared_machine', 'cpu_reserve_percent'} - policy.model_fields_set
    return canonical_digest(policy.model_dump(mode='json', exclude=absent))


def trust_readiness_blockers(machine, policy, config, observed, *, now=None) -> list[str]:
    """Require current execution prerequisites, never a pre-use acceptance pass."""
    at = now or datetime.now(timezone.utc)
    reasons = []
    if machine is None or policy is None or config is None:
        return ['machine_configuration_missing']
    if machine.machine_id != config.machine_id or machine.machine_id != policy.machine_id:
        reasons.append('machine_identity_mismatch')
    if machine.owner_user_id != policy.owner_user_id:
        reasons.append('owner_identity_mismatch')
    if machine.runtime_version != STABLE_RUNTIME_VERSION or config.runtime_version != STABLE_RUNTIME_VERSION:
        reasons.append('approved_runtime_not_observed')
    if not config.root_uuid or not config.pinned_host_key:
        reasons.append('pinned_worker_identity_missing')
    if policy.effective_cpu_cap(machine.total_cpus) < 1:
        reasons.append('shared_cpu_budget_exhausted')
    if any(value == 'failed' for value in (config.operational_execution, config.numeric_equivalence,
                                         config.startup_after_reboot)):
        reasons.append('known_acceptance_failure')
    from .scientific_acceptance_review import reviewed_scientific_failure
    if (config.execution_provenance.get('member_audit_state') == 'failed'
            or (config.execution_provenance.get('scientific_audit_state') == 'failed'
                and not reviewed_scientific_failure(config, policy, machine))):
        reasons.append('known_acceptance_failure')
    if not machine.metrics.available or not fresh(machine.metrics.observed_at, at) or not fresh(machine.last_heartbeat_at, at):
        reasons.append('fresh_machine_heartbeat_required')
    if observed is None:
        reasons.append('supervisor_observation_missing')
    else:
        if (observed.machine_id != machine.machine_id or not observed.observation_consistent
                or observed.transport_state.value != 'connected' or observed.supervisor_state.value != 'online'
                or observed.telemetry_state.value != 'live'):
            reasons.append('live_supervisor_required')
        if (observed.supervisor_reported_concurrent_units is None
                or observed.supervisor_reported_concurrent_units < config.target_concurrent_units):
            reasons.append('requested_capacity_not_observed')
        # Manual SSH nodes require genuine center-owned SSH evidence.
        # Invited dual-channel nodes retain both independent evidence paths.
        manual_ssh = (config.execution_provenance.get('onboarding', '').startswith('manual-ssh-')
                      and not config.control_plane_heartbeat_url and not config.machine_token_file)
        required_channels = ('ssh',) if manual_ssh else ('ssh', 'outbound')
        if any(name not in observed.connection_evidence
               or not observed.connection_evidence[name].healthy
               or observed.connection_evidence[name].transport_state.value != 'connected'
               or not fresh(observed.connection_evidence[name].observed_at, at)
               or not fresh(observed.connection_evidence[name].supervisor_at, at)
               or not fresh(observed.connection_evidence[name].metric_at, at)
               for name in required_channels):
            reasons.append('fresh_independent_channels_required')
    return list(dict.fromkeys(reasons))
