"""Read-only closeout view for self-service member machine acceptance.

This module never runs a probe or changes admission. It reports the latest
center-owned acceptance evidence and exact real-machine actions still required.
"""
from __future__ import annotations

from sqlalchemy import select

from .models import AcceptanceStatus, EnrollmentRecord, MachineExecutionConfig, MachineMode, MachinePolicy, SshAcceptanceRun
from .repository import EnrollmentRow, MachineExecutionConfigRow, PolicyRow, SshAcceptanceRow
from .ssh_acceptance import REQUIRED_CHECK_IDS

AUTOMATIC_CHECKS = {
    "member_admission_context", "ssh_transport", "root_initialized", "runtime_deployed",
    "safe_fake_task", "project_worker_task", "independent_heartbeat",
}
REAL_CHECKS = {
    "worker_environment", "concurrency_1", "cancel_python_start", "cancel_comsol_start",
    "cancel_solve", "cancel_transfer", "tunnel_recovery", "no_residual_processes",
    "startup_after_reboot",
}


def _required() -> set[str]:
    return (set(REQUIRED_CHECK_IDS) - {"concurrency_2", "concurrency_3"}) | {
        "member_admission_context", "independent_heartbeat", "startup_after_reboot",
    }


def _actions(run_id: str | None, missing: set[str]) -> list[dict]:
    if not run_id:
        return []
    result = []
    def add(check, command, *, disruptive=False, note=None):
        if check in missing:
            item={"check_id":check,"command":command,"disruptive":disruptive}
            if note:item["note"]=note
            result.append(item)
    add("worker_environment", ["ssh-acceptance-preflight", run_id],
        note="Read-only SSH/COMSOL/environment preflight.")
    add("concurrency_1", ["ssh-acceptance-submit", run_id, "1"],
        note="Run the fixed COMSOL acceptance task, then collect the returned external IDs with ssh-acceptance-collect.")
    for stage,check in (("python_start","cancel_python_start"),("comsol_start","cancel_comsol_start"),("solve","cancel_solve")):
        add(check, ["ssh-acceptance-cancel-stage", run_id, stage], disruptive=True,
            note="Cancels only the acceptance work-unit process tree.")
    add("cancel_transfer", ["ssh-acceptance-transfer-cancel", run_id, "<acceptance-external-run-id>"],
        disruptive=True, note="Use an acceptance external run ID produced by this same run.")
    add("tunnel_recovery", ["ssh-acceptance-tunnel-prepare", run_id], disruptive=True,
        note="Follow with ssh-acceptance-tunnel-cycle and ssh-acceptance-tunnel-verify for the same run.")
    add("no_residual_processes", ["ssh-acceptance-no-residual", run_id],
        note="Read-only scoped process inventory after the acceptance tasks finish.")
    add("startup_after_reboot", ["ssh-acceptance-reboot-arm", run_id], disruptive=True,
        note="Arm first, perform one real Windows reboot/login, then run ssh-acceptance-reboot-verify.")
    return result


def member_acceptance_status(repository, enrollment_id: str) -> dict:
    required=_required()
    with repository._session() as session:
        row=session.get(EnrollmentRow,enrollment_id)
        if row is None:
            raise KeyError("member enrollment not found")
        record=EnrollmentRecord.model_validate(row.payload)
        machine_id=record.machine_id
        latest=None
        if machine_id:
            latest=session.scalar(select(SshAcceptanceRow).where(
                SshAcceptanceRow.payload["worker_id"].as_string()==machine_id,
                (SshAcceptanceRow.payload['checks'][0]['check_id'].as_string() != 'scientific_context')
                | SshAcceptanceRow.payload['checks'][0]['check_id'].as_string().is_(None)
            ).order_by(SshAcceptanceRow.created_at.desc(),SshAcceptanceRow.run_id.desc()).limit(1))
        run=SshAcceptanceRun.model_validate(latest.payload) if latest is not None else None
        config_row=session.get(MachineExecutionConfigRow,machine_id) if machine_id else None
        config=MachineExecutionConfig.model_validate(config_row.payload) if config_row is not None else None
        policy_row=session.get(PolicyRow,machine_id) if machine_id else None
        policy=MachinePolicy.model_validate(policy_row.payload) if policy_row is not None else None

    checks={c.check_id:c for c in run.checks} if run is not None else {}
    duplicate_checks=sorted({c.check_id for c in run.checks if sum(x.check_id==c.check_id for x in run.checks)>1}) if run else []
    passed=sorted(k for k in required if k in checks and checks[k].status==AcceptanceStatus.PASSED)
    failed=sorted(k for k in required if k in checks and checks[k].status==AcceptanceStatus.FAILED)
    pending=sorted(k for k in required if k in checks and checks[k].status in {AcceptanceStatus.PENDING,AcceptanceStatus.RUNNING,AcceptanceStatus.WARNING})
    missing=sorted(required-set(checks))
    incomplete=set(missing)|set(pending)|set(failed)
    admitted=bool(record.member_admission_result and record.member_admission_result.get("state")=="admitted")
    recorded_enabled=bool(admitted and config and config.enabled and policy and policy.effective_mode()==MachineMode.OPEN
                          and policy.member_execution_limit and policy.member_execution_limit.active)
    return {
        "schema_version":1,
        "enrollment_id":record.enrollment_id,
        "machine_id":machine_id,
        "latest_run_id":run.run_id if run else None,
        "latest_run_status":run.status.value if run else None,
        "admission_state":(record.member_admission_result or {}).get("state","not-admitted"),
        "scientific_audit":(record.member_admission_result or {}).get("scientific_audit"),
        "audit_scope":(record.member_admission_result or {}).get("audit_scope","not_reported"),
        "recorded_execution_enabled":recorded_enabled,
        "finalizer_revalidates_live_health":True,
        "required_checks":sorted(required),
        "passed_checks":passed,
        "pending_checks":pending,
        "failed_checks":failed,
        "missing_checks":missing,
        "duplicate_checks":duplicate_checks,
        "automatic_checks":sorted(AUTOMATIC_CHECKS),
        "real_machine_checks":sorted(REAL_CHECKS),
        "real_acceptance_remaining":sorted(incomplete & REAL_CHECKS),
        "automatic_evidence_remaining":sorted(incomplete & AUTOMATIC_CHECKS),
        "ready_for_finalization":bool(run and not incomplete and not duplicate_checks and run.status==AcceptanceStatus.PASSED),
        "next_actions":_actions(run.run_id if run else None,incomplete),
    }
