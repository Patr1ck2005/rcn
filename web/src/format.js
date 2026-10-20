export function formatMb(value = 0) {
  return value >= 1024 ? `${(value / 1024).toFixed(1)} GB` : `${Math.round(value)} MB`;
}

export function formatIdle(seconds = 0) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

export function formatNumber(value, maximumFractionDigits = 1) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "-";
  return new Intl.NumberFormat("zh-CN", { maximumFractionDigits }).format(numeric);
}

export function formatPercent(value, maximumFractionDigits = 1) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? `${formatNumber(numeric, maximumFractionDigits)}%` : "未知";
}

export function formatDuration(seconds) {
  const numeric = Number(seconds);
  if (!Number.isFinite(numeric) || numeric < 0) return "暂无";
  if (numeric < 60) return `${Math.round(numeric)} 秒`;
  if (numeric < 3600) return `${Math.floor(numeric / 60)} 分 ${Math.round(numeric % 60)} 秒`;
  const hours = Math.floor(numeric / 3600);
  const minutes = Math.floor((numeric % 3600) / 60);
  return `${hours} 小时 ${minutes} 分`;
}

export function formatEta(seconds, confidence = "", lowerSeconds = null, upperSeconds = null) {
  if (seconds == null || seconds === "") return "暂无可靠估计";
  const duration = formatDuration(seconds);
  if (duration === "暂无") return "暂无可靠估计";
  const lower = Number(lowerSeconds);
  const upper = Number(upperSeconds);
  const range = Number.isFinite(lower) && Number.isFinite(upper) && upper > lower
    ? `${formatDuration(lower)}–${formatDuration(upper)}`
    : duration;
  return confidence && confidence !== "unknown" ? `${range} · ${confidence}` : range;
}

export function estimateEta({ completed = 0, total = 0, startedAt, now = Date.now(), etaSeconds = null, etaLowerSeconds = null, etaUpperSeconds = null, confidence = "", allowFallback = true } = {}) {
  const completedCount = Number(completed);
  const totalCount = Number(total);
  if (Number.isFinite(etaSeconds) && etaSeconds >= 0) {
    return { seconds: etaSeconds, confidence, label: formatEta(etaSeconds, confidence, etaLowerSeconds, etaUpperSeconds), source: "server" };
  }
  const started = new Date(startedAt || "").getTime();
  if (!allowFallback || !Number.isFinite(started) || completedCount <= 0 || totalCount <= completedCount || now <= started) {
    return { seconds: null, confidence: "unknown", label: "暂无可靠估计", source: "insufficient-samples" };
  }
  const elapsed = (now - started) / 1000;
  const rate = completedCount / elapsed;
  const seconds = Math.max(0, (totalCount - completedCount) / rate);
  return { seconds, confidence: confidence || "初步估计", label: formatEta(seconds, confidence || "初步估计"), source: "observed-throughput" };
}

export function unitItemCount(unit = null) {
  if (!unit) return 0;
  // Zero is the compact view's "count not stored" sentinel for blob-backed
  // identifier lists, so it must fall through instead of shadowing a real
  // worker-reported total_items value.
  return Number(
    unit.atomic_item_count
    || unit.total_items
    || unit.atomic_item_ids?.length
    || 0,
  );
}

export function jobProgressTotals(job = null) {
  const units = Array.isArray(job?.work_units) ? job.work_units : [];
  const declaredTotal = Number(job?.total_items ?? job?.atomic_item_count);
  const unitSum = units.reduce((sum, unit) => sum + unitItemCount(unit), 0);
  const fallbackCompleted = units.reduce(
    (sum, unit) => sum + (unit.status === "completed" ? unitItemCount(unit) : Number(unit.completed_items || 0)),
    0,
  );
  return {
    completed: Number(job?.completed_items ?? fallbackCompleted),
    total: Number.isFinite(declaredTotal) && declaredTotal > 0 ? declaredTotal : unitSum,
  };
}

export function unitEtaLabel(unit = null, jobEtaSeconds = null) {
  if (unitIsReconciling(unit)) return "等待对账 · 暂无可靠估计";
  const unitEta = unit?.eta_s;
  if (unitEta != null && Number.isFinite(Number(unitEta))) {
    return `Unit 剩余 ${formatEta(unitEta, unit.eta_confidence, unit.eta_lower_seconds, unit.eta_upper_seconds)}`;
  }
  const jobSeconds = jobEtaSeconds == null ? NaN : Number(jobEtaSeconds);
  if (Number.isFinite(jobSeconds) && jobSeconds >= 0) {
    return `Job 剩余约 ${formatDuration(jobSeconds)}`;
  }
  return "暂无 Unit 内部估计";
}

export function unitIsReconciling(unit = null) {
  if (!unit || ["completed", "failed_terminal", "failed_retriable"].includes(unit.status)) return false;
  if (unit.status === "reconcile_pending" || unit.activity_state === "reconcile_pending") return true;
  const latest = unit.attempts?.at(-1);
  return !latest?.finished_at && ["uncertain", "reconcile_pending", "cancel_pending"].includes(latest?.state);
}

const REASSIGNABLE_UNIT_STATUSES = new Set([
  "queued",
  "assigned",
  "running",
  "reconcile_pending",
  "failed_retriable",
  "cancelled",
]);

export function unitReassignable(unit = null) {
  if (!unit) return false;
  if (!REASSIGNABLE_UNIT_STATUSES.has(unit.status)) return false;
  const latestAttempt = Array.isArray(unit.attempts) && unit.attempts.length
    ? unit.attempts[unit.attempts.length - 1]
    : null;
  // A cancellation that is still propagating must finish before the pin step
  // can run; the server rejects the request and the UI should not offer it.
  if (latestAttempt?.state === "cancel_pending") return false;
  if (Number(unit.attempt_count || 0) >= Number(unit.max_attempts || 3)) return false;
  return true;
}

export function jobMachineDurations(job = null) {
  const units = Array.isArray(job?.work_units) ? job.work_units : [];
  const result = {};
  for (const unit of units) {
    const attempts = Array.isArray(unit?.attempts) ? unit.attempts : [];
    for (const attempt of attempts) {
      if (attempt?.state !== "completed" || !attempt.machine_id) continue;
      const start = new Date(attempt.started_at || "").getTime();
      const finish = new Date(attempt.finished_at || "").getTime();
      if (!Number.isFinite(start) || !Number.isFinite(finish) || finish <= start) continue;
      const minutes = (finish - start) / 60000;
      const entry = result[attempt.machine_id] || { count: 0, totalMinutes: 0, maxMinutes: 0 };
      entry.count += 1;
      entry.totalMinutes += minutes;
      entry.maxMinutes = Math.max(entry.maxMinutes, minutes);
      result[attempt.machine_id] = entry;
    }
  }
  return result;
}

// Cumulative completed-atoms series derived strictly from real attempt
// timestamps (collected_at, falling back to finished_at). Returns null when
// no unit carries a usable completion timestamp - never fabricates points.
export function jobCompletionSeries(job = null) {
  const units = Array.isArray(job?.work_units) ? job.work_units : [];
  const points = [];
  for (const unit of units) {
    const attempts = Array.isArray(unit?.attempts) ? unit.attempts : [];
    const completed = attempts.filter((attempt) => attempt?.state === "completed");
    const attempt = completed[completed.length - 1];
    if (!attempt) continue;
    const at = new Date(attempt.collected_at || attempt.finished_at || "").getTime();
    if (!Number.isFinite(at)) continue;
    points.push({ at, items: unitItemCount(unit) });
  }
  if (!points.length) return null;
  points.sort((left, right) => left.at - right.at);
  let cumulative = 0;
  const series = points.map((point) => {
    cumulative += point.items;
    return { at: point.at, items: cumulative };
  });
  const denominator = Number(job?.atomic_item_count) > 0 ? Number(job.atomic_item_count) : series[series.length - 1].items;
  return { denominator, points: series };
}

export function attemptSegments(unit = null) {
  const attempts = Array.isArray(unit?.attempts) ? unit.attempts : [];
  const segments = [];
  for (const attempt of attempts) {
    const start = new Date(attempt?.assigned_at || attempt?.started_at || "").getTime();
    const end = new Date(attempt?.finished_at || attempt?.collected_at || "").getTime();
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) continue;
    segments.push({ start, end, state: attempt.state || "assigned", machine: attempt.machine_id });
  }
  return segments;
}

export function jobTimeWindow(job = null) {
  let min = Infinity;
  let max = -Infinity;
  const units = Array.isArray(job?.work_units) ? job.work_units : [];
  for (const unit of units) {
    for (const segment of attemptSegments(unit)) {
      min = Math.min(min, segment.start);
      max = Math.max(max, segment.end);
    }
  }
  return Number.isFinite(min) && max > min ? { min, max } : null;
}

export function formatAge(value, now = Date.now()) {
  if (!value) return "暂无数据";
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return "暂无数据";
  const seconds = Math.max(0, Math.floor((now - timestamp) / 1000));
  if (seconds < 60) return `${seconds} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  return `${Math.floor(seconds / 3600)} 小时前`;
}

export function capacityDisplay({ effective = 0, target = 0, hardCap = 0, pressureState = "normal" } = {}) {
  const constrained = effective < target;
  const pressureLabels = {
    pressured: "压力限制",
    telemetry_stale: "遥测保护",
    override: "临时覆盖",
    candidate: "压力候选",
    normal: "无运行时降容",
  };
  return {
    value: `${effective} / ${target}`,
    detail: `有效 ${effective} · 目标 ${target} · 硬上限 ${hardCap} · ${pressureLabels[pressureState] || pressureState}`,
    constrained,
  };
}

export function gpuDisplay(machine = {}) {
  const metrics = machine.metrics || {};
  const samples = (metrics.gpu || []).filter(
    (item) => item.available !== false && item.utilization_percent != null,
  );
  const registeredCount = Number(machine.total_gpus) || 0;
  const count = Math.max(registeredCount, samples.length);
  const explicitlyAbsent = count === 0 && !(metrics.gpu || []).length
    && (!metrics.gpu_status || metrics.gpu_status === "not_detected");
  const current = samples.length
    ? samples.reduce((sum, item) => sum + Number(item.utilization_percent), 0) / samples.length
    : 0;
  const value = samples.length
    ? samples.reduce((sum, item) => sum + Number(item.utilization_average_percent ?? item.utilization_percent), 0) / samples.length
    : 0;
  const fiveMinute = samples.length
    ? samples.reduce((sum, item) => sum + Number(item.utilization_5m_average_percent ?? item.utilization_average_percent ?? item.utilization_percent), 0) / samples.length
    : 0;
  const peak = samples.length
    ? Math.max(...samples.map((item) => Number(item.utilization_peak_percent ?? item.utilization_percent)))
    : 0;
  const detail = explicitlyAbsent
    ? "未配置 GPU"
    : samples.length ? (() => {
      const used = samples.reduce((sum, item) => sum + Number(item.memory_used_mb || 0), 0);
      const total = samples.reduce((sum, item) => sum + Number(item.memory_total_mb || 0), 0);
      const temperatures = samples.map((item) => item.temperature_c).filter((item) => item != null);
      const memory = total ? ` · ${formatMb(used)}/${formatMb(total)}` : "";
      const temperature = temperatures.length
        ? ` · ${formatNumber(Math.max(...temperatures))}°C`
        : "";
      const sampleCount = Math.min(...samples.map((item) => Number(item.sample_count || 0)));
      const quality = samples.every((item) => item.sampling_quality === "nvml") ? "NVML" : "降级采样";
      return `${count} 张 · 60 秒均值${memory}${temperature} · ${quality} · ${sampleCount} 样本`;
    })() : "GPU 遥测冻结";
  const names = [...new Set(samples.map((item) => item.name).filter(Boolean))].join(" / ");
  const summary = explicitlyAbsent
    ? "未配置"
    : samples.length
      ? `${count} 张 · 60 秒均 ${formatNumber(value)}% · 瞬时 ${formatNumber(current)}%${names ? ` · ${names}` : ""}`
      : `${count || "已配置"} · 遥测冻结`;
  const sampleCount = samples.length
    ? Math.min(...samples.map((item) => Number(item.sample_count || 0)))
    : 0;
  const quality = samples.length && samples.every((item) => item.sampling_quality === "nvml")
    ? "NVML"
    : "降级";
  const tableDetail = explicitlyAbsent
    ? "未配置 GPU"
    : samples.length
      ? `${quality} · ${sampleCount ? `${sampleCount} 样本` : "采样不足"}`
      : "遥测冻结";
  return { count, detail, tableDetail, explicitlyAbsent, inactive: !samples.length, names, samples, summary, value, average: current, current, fiveMinute, peak };
}

export function statusLabel(value) {
  return {
    open: "开放", drain: "排空", paused: "暂停", emergency_stop: "紧急停止",
    queued: "排队", prepared: "已预备", assigned: "已分配", running: "运行中",
    finalizing: "导出终结中", collecting: "回收中", completed: "完成", cancelled: "已取消",
    failed_retriable: "可重试失败", failed_terminal: "终止失败", awaiting_approval: "待审批",
    staged: "已暂存", cancel_pending: "取消中", reconcile_pending: "等待对账", abandoned: "已放弃旧尝试", interrupted: "已中断",
    awaiting_environment: "等待环境", needs_attention: "需要处理", recoverable: "可恢复",
    pending: "待检查", passed: "通过", warning: "需核查", failed: "失败", blocked: "受阻",
    connected: "SSH 已连接", disconnected: "SSH 已断开", unknown: "状态未知",
    online: "执行器在线", stale: "数据过期", unavailable: "不可用", live: "遥测实时",
    healthy: "健康", delayed: "延迟", offline: "离线", telemetry_delay: "遥测延迟",
    transport_disconnected: "传输断开", executor_unavailable: "执行器不可用",
  }[value] || value;
}
