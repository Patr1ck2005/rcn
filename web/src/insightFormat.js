// Unknown is never rendered as zero. Durations describe a snapshot, not a countdown.
export const WORK_STATES = [
  { key: "completed", label: "已完成", color: "var(--green)" },
  { key: "running", label: "运行中", color: "var(--cyan)" },
  { key: "waiting", label: "待派发", color: "var(--insight-wait)" },
  { key: "collecting", label: "回收 / 对账", color: "var(--violet)" },
  { key: "attention", label: "受阻 / 失败", color: "var(--amber)" },
  { key: "cancelled", label: "已取消", color: "var(--faint)" },
];
export function insightScopeLabels(data) {
  const own = data?.scope?.jobs === "own";
  const filtered = own || Boolean(data?.scope?.projects_filtered);
  return { own, filtered, title: own ? "我的任务总览" : filtered ? "可见任务总览" : "全网运行总览",
    projects: own ? "我的全部项目" : filtered ? "全部可见项目" : "全网 / 全部项目",
    tasks: own ? "我的任务" : filtered ? "可见任务" : "全网任务" };
}

export function numberText(value, digits = 1) {
  return value !== null && value !== undefined && typeof value !== "boolean" && !(typeof value === "string" && value.trim() === "") && Number.isFinite(Number(value))
    ? new Intl.NumberFormat("zh-CN", { maximumFractionDigits: digits }).format(Number(value)) : "—";
}
export function percentText(value) { const label = numberText(value); return label === "—" ? label : `${label}%`; }
export function durationText(seconds) {
  if (seconds == null || typeof seconds === "boolean" || seconds === "" || !Number.isFinite(Number(seconds)) || seconds < 0) return "待估计";
  if (seconds === 0) return "无待算工作";
  const minutes = Math.max(1, Math.ceil(seconds / 60));
  if (minutes < 60) return `${minutes} 分钟`;
  if (minutes < 1440) return `${Math.floor(minutes / 60)} 小时${minutes % 60 ? ` ${minutes % 60} 分` : ""}`;
  return `${Math.floor(minutes / 1440)} 天 ${Math.ceil(minutes % 1440 / 60)} 小时`;
}
export const FORECAST_REASON = {
  no_work: "暂无待算工作", max_project_finish: "各项目并行，取最晚预计完工",
  incomplete_source: "数据不完整，暂停完工预测", partial_project_forecasts: "部分项目尚不具备估计条件",
  blocked_work: "存在受阻工作，需先恢复条件", recovery_or_missing_duration: "回收 / 对账、明显超时或耗时证据不足",
  waiting_for_dispatch_or_fresh_telemetry: "等待首次派发或新鲜遥测",
  observed_work_rate: "依据近期实测工作量完成速率",
  current_slots_calibrated: "任务历史校准 × 当前已获并发",
  current_slots_declared: "申报耗时 × 当前已获并发，初步估计",
  outside_forecast_horizon: "超出合理预测范围",
};
export function forecastText(forecast, stale = false) {
  if (stale) return { value: "待刷新", detail: "上次快照已过期，暂停显示完工承诺" };
  if (!forecast) return { value: "待估计", detail: "尚无预测证据" };
  return { value: durationText(forecast.seconds), detail: FORECAST_REASON[forecast.basis] || "按当前队列估算" };
}
export function projectRows(data, query = "") {
  const needle = query.trim().toLowerCase();
  return (data?.projects || []).filter(p => p.project_id.toLowerCase().includes(needle));
}
export function countsTotal(counts) { return WORK_STATES.reduce((n, s) => n + (Number(counts?.[s.key]) || 0), 0); }

export function intervalText(seconds) {
  if (seconds == null || !Number.isFinite(Number(seconds)) || seconds <= 0) return "未知时长";
  if (seconds % 3600 === 0) return `${seconds / 3600} 小时`;
  if (seconds % 60 === 0) return `${seconds / 60} 分钟`;
  return `${Math.floor(seconds / 60)} 分 ${Math.round(seconds % 60)} 秒`;
}
