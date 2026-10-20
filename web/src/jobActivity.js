import { estimateEta, jobProgressTotals, statusLabel, unitIsReconciling } from "./format";

export function reconciliationState(job = {}) {
  const units = (job.work_units || []).filter(unitIsReconciling);
  const pending = Number(job.reconciliation_unit_count || 0) > 0
    || job.activity_phase === "reconcile_pending"
    || job.eta_blocked_reason === "awaiting_reconciliation"
    || units.length > 0;
  const machineIds = [...new Set([
    ...(job.reconciliation_machine_ids || []),
    ...units.map((unit) => unit.attempts?.at(-1)?.machine_id || unit.assigned_machine_id),
  ].filter((id) => typeof id === "string" && id.length > 0))];
  return { pending, count: Number(job.reconciliation_unit_count || units.length), machineIds };
}

export function currentJobPhase(job = {}) {
  if (reconciliationState(job).pending) return "reconcile_pending";
  if (job.activity_phase) return job.activity_phase;
  const units = job.work_units || [];
  if (units.length && units.every((unit) => unit.status === "completed")) return "completed";
  if (units.some((unit) => unit.status === "collecting" || unit.dispatch_phase === "collecting")) return "collecting";
  if (units.some((unit) => unit.dispatch_phase === "finalizing" || unit.activity_state === "finalizing")) return "finalizing";
  if (units.some((unit) => unit.status === "running")) return "running";
  if (units.some((unit) => unit.status === "assigned")) return "assigned";
  if (units.some((unit) => unit.dispatch_phase === "prepared" || unit.status === "prepared")) return "prepared";
  return job.status || "queued";
}

export function reconciliationLabel(job = {}) {
  const { machineIds } = reconciliationState(job);
  return machineIds.length ? `等待 ${machineIds.join("、")} 对账` : "等待对账";
}

export function jobStatusPresentation(job = {}) {
  return reconciliationState(job).pending
    ? { value: "reconcile_pending", text: reconciliationLabel(job) }
    : { value: job.status };
}

export function jobPhaseLabel(job = {}) {
  return currentJobPhase(job) === "reconcile_pending" ? reconciliationLabel(job) : statusLabel(currentJobPhase(job));
}

export function jobEta(job = {}, now = Date.now()) {
  // An explicitly withdrawn server estimate must not be reconstructed from
  // cumulative progress or an old worker countdown in another view.
  if (reconciliationState(job).pending || job.eta_blocked_reason || job.eta_confidence === "unknown") {
    return { seconds: null, confidence: "unknown", label: "暂无可靠估计", source: "server-withdrawn", at: null };
  }
  const { completed, total } = jobProgressTotals(job);
  const result = estimateEta({
    completed, total, now, startedAt: job.execution_started_at || job.started_at,
    etaSeconds: job.eta_seconds == null ? null : Number(job.eta_seconds),
    etaLowerSeconds: job.eta_lower_seconds == null ? null : Number(job.eta_lower_seconds),
    etaUpperSeconds: job.eta_upper_seconds == null ? null : Number(job.eta_upper_seconds),
    confidence: job.eta_confidence,
  });
  return { ...result, at: result.seconds == null ? null : job.eta_at || null };
}

export function jobEnvironmentLabel(job = {}) {
  const reconciliation = reconciliationState(job);
  const units = job.work_units || [];
  const queued = Number(job.queued_unit_count || 0) > 0
    || units.some((unit) => ["queued", "prepared", "failed_retriable"].includes(unit.status));
  if (reconciliation.pending && !queued) return `${reconciliationLabel(job)} · 没有待派发单元`;
  if (job.execution_environment_state === "not_requested" && !queued && !reconciliation.pending) {
    const live = units.some((unit) => ["assigned", "running", "collecting", "reconcile_pending"].includes(unit.status)
      || (unit.attempts || []).some((attempt) => !attempt.finished_at && ["assigned", "submitting", "running", "cancel_pending", "reconcile_pending", "uncertain", "collecting"].includes(attempt.state)));
    if (!live) return "历史执行已结束；当前环境按需检查";
  }
  const environment = job.execution_environment;
  if (!environment) return "环境状态未知";
  if (environment.status === "executable") {
    const slots = environment.capacity_hint?.eligible_slots || 0;
    return slots > 0 ? `环境就绪 · ${slots} 可用 slot` : "环境就绪 · 当前容量已满";
  }
  if (environment.status === "blocked_by_approval") return "等待当前 Runtime 审批";
  const reasons = (environment.reason_codes || []).map((reason) => ({
    machine_runtime_not_ready: "机器 runtime 未就绪", supervisor_not_online: "执行器未在线",
    machine_not_open: "机器未开放", machine_owner_approval_missing: "缺少机器所有者授权",
    machine_capability_mismatch: "机器能力不匹配", capacity_temporarily_full: "容量暂时已满",
    no_compatible_machine: "没有兼容机器", project_or_profile_not_enabled: "项目或 Profile 未启用",
  }[reason] || reason));
  return reasons.length ? `等待执行环境 · ${reasons.slice(0, 2).join("、")}` : "等待执行环境";
}

export function reconciliationNotice(job = {}) {
  const { pending, count } = reconciliationState(job);
  if (!pending) return "";
  return `${count > 0 ? `${count} 个单元执行状态未知，` : "执行状态未知，"}${reconciliationLabel(job)}；预计完成时间暂不可用。`;
}
