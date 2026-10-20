import { useMutationGuard } from "./useMutationGuard";
import { useEffect, useMemo, useRef, useState } from "react";
import { usePageRefresh } from "./usePageRefresh";
import { Activity, AlertTriangle, ArrowLeft, Boxes, Gauge, Server, Settings2, TerminalSquare } from "lucide-react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { api } from "./api";
import { DataLoadState } from "./AsyncState";
import { MachineControlDialog } from "./ControlDialogs";
import { ExecutionTuningEditor, MachinePolicyEditor } from "./MachineSettings";
import { formatNumber, formatPercent } from "./format";
import { HelpLink } from "./HelpSystem";
import { isHistorical } from "./fleetRecords";

const tabs = [
  ["overview", "概览", Server], ["performance", "性能", Gauge], ["tasks", "任务", Boxes],
  ["control", "控制", TerminalSquare], ["events", "事件", Activity], ["config", "配置", Settings2],
];
const time = (value) => value ? new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date(value)) : "-";
const integer = (value) => formatNumber(value, 0);

function ChartPanel({ title, unit, data, keys }) {
  const valueFormatter = (value, name) => [unit === "%" ? formatPercent(value) : formatNumber(value), name];
  return <section className="chart-panel"><header><div><h3>{title}</h3><span>{unit}</span></div><small>{data.length} 个真实采样</small></header><div className="chart-body">{data.length
    ? <ResponsiveContainer width="100%" height="100%"><LineChart data={data}><CartesianGrid stroke="var(--line)" vertical={false} /><XAxis dataKey="at" type="number" domain={["dataMin", "dataMax"]} tickFormatter={(value) => new Date(value).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" })} minTickGap={42} /><YAxis width={44} tickFormatter={(value) => unit === "%" ? formatPercent(value, 0) : formatNumber(value)} domain={unit === "%" ? [0, 100] : ["auto", "auto"]} /><Tooltip labelFormatter={(value) => time(value)} formatter={valueFormatter} /><defs><clipPath id={`clip-${title}`}><rect x="0" y="0" width="100%" height="100%" /></clipPath></defs>{keys.map(([key, color, name]) => <Line key={key} dataKey={key} name={name} stroke={color} dot={false} connectNulls={false} isAnimationActive={false} strokeWidth={1.6} />)}</LineChart></ResponsiveContainer>
    : <div className="chart-empty">该时间窗口没有采样，不进行插值</div>}</div></section>;
}

function Details({ rows }) {
  return <dl className="detail-grid">{rows.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{String(value ?? "-")}</dd></div>)}</dl>;
}

const metricPercent = (metrics, value) => metrics?.available === false || value == null
  ? "未知"
  : formatPercent(value);

const attributedPercent = (metrics, value) => ["job_object", "process_tree"].includes(metrics?.cpu_attribution_quality)
  ? metricPercent(metrics, value)
  : "未知（归因不可用）";

export default function MachineDetail({ admin: administrator = false, machines = [], roles = [], actorId = "", settings = {}, onGlobalRefresh }) {
  const { machineId } = useParams();
  const historical = machines.some((machine) => machine.machine_id === machineId && isHistorical(machine));
  const admin = administrator && !historical;
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") || "overview";
  const window = params.get("window") || "1h";
  const [detail, setDetail] = useState(null);
  const [samples, setSamples] = useState([]);
  const [error, setError] = useState("");
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [metricsError, setMetricsError] = useState("");
  const [metricsRetry, setMetricsRetry] = useState(0);
  const [control, setControl] = useState(null);
  const [targetCapacity, setTargetCapacity] = useState(0);
  const [hardCapacity, setHardCapacity] = useState(0);
  const [showAllPressureEvents, setShowAllPressureEvents] = useState(false);
  const [consentBusy, setConsentBusy] = useState(false);
  const mutation = useMutationGuard();
  const staleAfterMs = Math.max(5000, Number(settings.telemetry_policy?.stale_after_s || 45) * 1000);
  const requestGeneration = useRef(0);
  const load = async (background = false) => {
    const generation = ++requestGeneration.current;
    try {
      const next = await api(`/v1/machines/${machineId}/detail`);
      if (generation !== requestGeneration.current) return;
      setDetail(next);
      if (!background) {
      setTargetCapacity(next.execution_config?.target_concurrent_units ?? 0);
      setHardCapacity(next.execution_config?.max_concurrent_units ?? 1);
      }
      setError("");
    }
    catch (caught) { if (generation === requestGeneration.current) setError(caught.message); }
  };
  useEffect(() => { setDetail(null); load(); return () => { ++requestGeneration.current; }; }, [machineId]);
  usePageRefresh(async () => { await load(true); setMetricsRetry((value) => value + 1); }, { resources: ["machines", "machine-detail"] });
  useEffect(() => { setSamples([]); }, [machineId, tab, window]);
  useEffect(() => {
    if (tab !== "performance") return;
    let active = true;
    setMetricsError(""); setMetricsLoading(true);
    api(`/v1/machines/${machineId}/metrics?window=${window}`).then((items) => { if (active) setSamples(items); }).catch((caught) => { if (active) setMetricsError(caught.message); }).finally(() => { if (active) setMetricsLoading(false); });
    return () => { active = false; };
  }, [machineId, tab, window, metricsRetry]);
  const chartData = useMemo(() => samples.map((sample) => {
    const metrics = sample.metrics || {};
    const gpu = metrics.gpu?.[0];
    const available = metrics.available !== false;
    const attributionAvailable = ["job_object", "process_tree"].includes(metrics.cpu_attribution_quality);
    return {
      at: new Date(sample.recorded_at).getTime(),
      cpu: available ? metrics.cpu_current_percent ?? metrics.cpu_total_percent : null,
      cpuAverage: available ? metrics.cpu_average_percent : null,
      cpuPeak: available ? metrics.cpu_peak_percent : null,
      networkCpu: available && attributionAvailable ? metrics.network_cpu_percent : null,
      externalCpu: available && attributionAvailable ? metrics.external_cpu_percent : null,
      memory: available && metrics.total_memory_mb ? metrics.memory_used_mb / metrics.total_memory_mb * 100 : null,
      gpu: gpu?.available ? gpu.utilization_percent : null,
      gpuAverage: gpu?.available ? gpu.utilization_average_percent : null,
      gpuFiveMinute: gpu?.available ? gpu.utilization_5m_average_percent : null,
      gpuPeak: gpu?.available ? gpu.utilization_peak_percent : null,
      gpuMemory: gpu?.memory_total_mb ? gpu.memory_used_mb / gpu.memory_total_mb * 100 : null,
      temperature: gpu?.temperature_c ?? null,
      disk: available && metrics.total_disk_mb ? metrics.disk_used_mb / metrics.total_disk_mb * 100 : null,
    };
  }), [samples]);
  const sampleGaps = useMemo(() => {
    const ordered = [...samples].sort((left, right) => new Date(left.recorded_at) - new Date(right.recorded_at));
    return ordered.slice(1).map((sample, index) => {
      const previous = ordered[index];
      const durationMs = new Date(sample.recorded_at) - new Date(previous.recorded_at);
      return durationMs > staleAfterMs ? { start: previous.recorded_at, end: sample.recorded_at, durationMs } : null;
    }).filter(Boolean);
  }, [samples, staleAfterMs]);
  if (error && !detail) return <main className="app-page"><DataLoadState label="正在读取机器详情" error={error} onRetry={load} /></main>;
  if (!detail) return <main className="app-page"><DataLoadState label="正在读取机器详情" /></main>;
  const machine = detail.machine;
  const policy = detail.policy || {};
  const runtime = detail.operational_status || {};
  const config = detail.execution_config || {};
  const pressurePolicy = settings.pressure_policy || {};
  const pressureEvents = detail.events.filter((event) => event.event_type.includes("pressure") || event.event_type.includes("capacity"));
  const hardCap = Math.min(policy.max_concurrent_units || 0, config.max_concurrent_units || policy.max_concurrent_units || 0);
  const canEditPolicy = !historical && (admin || (roles.includes("machine_owner") && machine.owner_user_id === actorId));
  const setTab = (value) => setParams((current) => { current.set("tab", value); return current; });
  const setWindow = (value) => setParams((current) => { current.set("window", value); return current; });
  const complete = async () => { await load(); await onGlobalRefresh?.(); };
  const updateExternalConsent = (authorized) => mutation.run(async () => {
    setConsentBusy(true); setError("");
    try {
      await api(`/v1/machines/${machineId}/external-comsol-consent`, {
        method: "PUT", body: JSON.stringify({ authorized }),
      });
      await complete();
    } catch (caught) { setError(caught.message); }
    finally { setConsentBusy(false); }
  });
  return <main className="app-page machine-detail-page"><div className="detail-title"><Link className="icon-button" title="返回 Fleet" to="/app/fleet"><ArrowLeft size={18} /></Link><div><span>MACHINE / {machine.machine_id}</span><h1>{machine.display_name || machine.machine_id}</h1><p>{machine.owner_user_id} · {runtime.supervisor_state || "unknown"} · {runtime.telemetry_state || "unknown"}</p></div><HelpLink topic="machineHealth" /><div className="detail-capacity"><small>有效 / 目标 / 实报 / 硬上限</small><strong>{runtime.effective_capacity ?? runtime.effective_comsol_concurrency ?? 0} / {config.target_concurrent_units ?? hardCap} / {runtime.supervisor_reported_concurrent_units ?? "-"} / {hardCap}</strong></div></div>
    <nav className="detail-tabs machine-detail-tabs" aria-label="机器详情">{tabs.map(([value, text, Icon]) => <button key={value} className={tab === value ? "active" : ""} title={`查看${text}`} aria-label={`查看${text}`} onClick={() => setTab(value)}><Icon size={15} />{text}</button>)}</nav>
    {error && <div className="inline-error">{error}</div>}
    {historical && <p className="fleet-scope-note">已撤销 · 历史记录：仅供查看详情和审计，不提供控制或配置修改。</p>}
    {tab === "performance" && (metricsLoading || metricsError) && <div className="performance-load-state"><DataLoadState label={`正在加载最近 ${window} 的遥测`} error={metricsError} onRetry={() => setMetricsRetry((value) => value + 1)} /></div>}
    {tab === "overview" && <section className="detail-section"><header><h2>连接与控制</h2></header><Details rows={[["传输状态", runtime.transport_state || "unknown"], ["执行器状态", runtime.supervisor_state || "unavailable"], ["遥测状态", runtime.telemetry_state || "unavailable"], ["控制状态", runtime.control_state || "executor_unavailable"], ["CPU 归因质量", machine.metrics?.cpu_attribution_quality || "unavailable"], ["GPU 采样", machine.metrics?.gpu?.[0] ? `${machine.metrics.gpu[0].sampling_quality} · ${integer(machine.metrics.gpu[0].sample_count || 0)} 样本 · 60 秒均 ${formatPercent(machine.metrics.gpu[0].utilization_average_percent ?? machine.metrics.gpu[0].utilization_percent)} · 5 分钟均 ${formatPercent(machine.metrics.gpu[0].utilization_5m_average_percent ?? machine.metrics.gpu[0].utilization_percent)}` : "无 GPU"]]} /></section>}
    {tab === "overview" && <div className="detail-columns"><section className="detail-section"><header><h2>运行概览</h2></header><Details rows={[["所有者模式", policy.owner_mode], ["管理员覆盖", policy.admin_mode_override || "无"], ["最终有效模式", policy.admin_mode_override || policy.owner_mode], ["压力状态", runtime.pressure_state], ["Supervisor 实报并发", runtime.supervisor_reported_concurrent_units ?? "未知"], ["容量漂移", runtime.capacity_drift ? runtime.capacity_drift_reason : "无"], ["容量原因", runtime.capacity_reason], ["执行器心跳", time(runtime.last_supervisor_heartbeat_at)], ["遥测采样", time(runtime.last_metric_at)]]} /></section><section className="detail-section"><header><h2>资源快照</h2></header><Details rows={[["整机 CPU 当前 / 均值 / 峰值", [machine.metrics?.cpu_current_percent ?? machine.metrics?.cpu_total_percent, machine.metrics?.cpu_average_percent, machine.metrics?.cpu_peak_percent].map((value) => metricPercent(machine.metrics, value)).join(" / ")], ["Network / 外部 CPU", [machine.metrics?.network_cpu_percent, machine.metrics?.external_cpu_percent].map((value) => attributedPercent(machine.metrics, value)).join(" / ")], ["内存", machine.metrics?.available === false ? "未知" : `${integer((machine.metrics?.memory_used_mb || 0) / 1024)} / ${integer((machine.total_memory_mb || 0) / 1024)} GiB`], ["GPU 当前 / 均值 / 峰值", machine.total_gpus ? (machine.metrics?.gpu?.[0]?.available === false || !machine.metrics?.gpu?.[0] ? "未知" : `${formatPercent(machine.metrics.gpu[0].utilization_percent)} / ${formatPercent(machine.metrics.gpu[0].utilization_average_percent ?? machine.metrics.gpu[0].utilization_percent)} / ${formatPercent(machine.metrics.gpu[0].utilization_peak_percent ?? machine.metrics.gpu[0].utilization_percent)}`) : "无 GPU"], ["磁盘", machine.metrics?.available === false ? "未知" : `${integer((machine.metrics?.free_disk_mb || 0) / 1024)} GiB 可用`], ["外部计算进程", machine.metrics?.available === false ? "未知" : integer(runtime.external_process_count ?? machine.metrics?.external_process_count ?? runtime.external_comsol_process_count ?? 0)], ["活动 Unit", integer(machine.metrics?.running_units || 0)]]} /></section></div>}
    {tab === "performance" && <><div className="performance-toolbar"><div className="window-switch">{["1h", "6h", "24h"].map((value) => <button className={window === value ? "active" : ""} title={`查看最近 ${value} 的遥测`} aria-label={`查看最近 ${value} 的遥测`} key={value} onClick={() => setWindow(value)}>{value}</button>)}</div><div className="threshold-note"><AlertTriangle size={15} /><span>当前策略：CPU ≥{pressurePolicy.external_cpu_threshold_percent ?? 10}% 或 GPU ≥{pressurePolicy.external_gpu_threshold_percent ?? 40}%；内存模式 {pressurePolicy.memory_mode || "resource_gate_only"}；进入 / 解除 {pressurePolicy.enter_after_seconds ?? 30}s / {pressurePolicy.clear_after_seconds ?? 120}s。缺失区间不插值。</span></div></div><div className="chart-grid"><ChartPanel title="整机 CPU" unit="%" data={chartData} keys={[["cpu", "#15936d", "当前"], ["cpuAverage", "#3184a1", "短窗均值"], ["cpuPeak", "#c88934", "窗口峰值"]]} /><ChartPanel title="CPU 归因" unit="%" data={chartData} keys={[["networkCpu", "#177aa6", "Network"], ["externalCpu", "#b45d37", "外部负载"]]} /><ChartPanel title="内存" unit="%" data={chartData} keys={[["memory", "#3184a1", "内存"]]} /><ChartPanel title="GPU 与显存" unit="%" data={chartData} keys={[["gpu", "#8b6ab4", "GPU 当前"], ["gpuAverage", "#15936d", "GPU 均值"], ["gpuPeak", "#d46370", "GPU 峰值"], ["gpuMemory", "#c88934", "显存"]]} /><ChartPanel title="GPU 温度" unit="°C" data={chartData} keys={[["temperature", "#d46370", "温度"]]} /><ChartPanel title="磁盘" unit="%" data={chartData} keys={[["disk", "#697a71", "磁盘"]]} /></div><div className="detail-columns performance-evidence"><section className="detail-section"><header><h2>缺失与 stale 区间</h2><span>{sampleGaps.length} 段</span></header><div className="gap-list">{sampleGaps.slice(-30).map((gap) => <div key={`${gap.start}-${gap.end}`}><time>{time(gap.start)} – {time(gap.end)}</time><b>{integer(gap.durationMs / 1000)}s</b></div>)}{!sampleGaps.length && <p>当前窗口内没有超过 {integer(staleAfterMs / 1000)} 秒的采样缺口。</p>}</div></section><section className="detail-section"><header><div><h2>压力与容量事件</h2><span>可追溯判定</span></div>{pressureEvents.length > 12 && <button className="text-button" title={showAllPressureEvents ? "收起压力事件" : `展开全部 ${pressureEvents.length} 条压力事件`} onClick={() => setShowAllPressureEvents(!showAllPressureEvents)}>{showAllPressureEvents ? "收起" : `查看全部 ${pressureEvents.length} 条`}</button>}</header><div className="deep-list">{pressureEvents.slice(0, showAllPressureEvents ? pressureEvents.length : 12).map((event) => <div key={event.event_id}><Activity size={15} /><span><b>{event.event_type}</b><small>{time(event.created_at)} · {event.details?.reason || runtime.capacity_reason}</small></span><code>#{event.sequence}</code></div>)}{!pressureEvents.length && <p>当前没有压力或容量变化事件。</p>}</div></section></div></>}
    {tab === "tasks" && <section className="detail-section"><header><h2>关联任务</h2><span>{detail.jobs.length} 个</span></header><div className="deep-list">{detail.jobs.map((job) => <Link key={job.job_id} to={`/app/runs/${job.job_id}`}><Boxes size={16} /><span><b>{job.job_id}</b><small>{job.project_id} · {job.status}</small></span></Link>)}{!detail.jobs.length && <p>当前没有关联任务。</p>}</div></section>}
    {tab === "control" && <section className="detail-section"><header><h2>机器控制</h2><span>所有操作均需 preview / confirm</span></header>{admin ? <><div className="target-capacity-editor"><label>目标并发<input aria-label="目标并发" title="设置该机器允许同时运行的 Unit 数量" type="number" min="0" max={hardCap} value={targetCapacity} onChange={(event) => setTargetCapacity(Math.max(0, Math.min(hardCap, Number(event.target.value))))} /></label><span>已验收硬上限 {config.accepted_hard_capacity_units ?? hardCap}；当前有效 {runtime.effective_capacity ?? runtime.effective_comsol_concurrency ?? 0}。</span><button title="预览目标并发变更，确认后才会生效" onClick={() => setControl({ action: "set_target_capacity", title: `目标并发 ${targetCapacity}`, targets: [{ machine_id: machineId, target_concurrent_units: targetCapacity }] })}>预览调整</button></div><div className="target-capacity-editor"><label>硬上限<input aria-label="已验收硬上限" title="设置经验收允许的并发硬上限" type="number" min="1" max="64" value={hardCapacity} onChange={(event) => setHardCapacity(Math.max(1, Math.min(64, Number(event.target.value))))} /></label><span>{config.hard_capacity_pending_acceptance ? "管理员强制 · 待 Agent 验收" : "已验收硬上限"}；提高时必须填写原因。</span><button title="预览硬上限变更，提升上限需要填写原因" onClick={() => setControl({ action: "set_hard_capacity", title: `管理员硬上限 ${hardCapacity}`, targets: [{ machine_id: machineId, hard_capacity_units: hardCapacity }] })}>预览硬上限</button>{config.hard_capacity_pending_acceptance && <button title="将最新硬上限绑定到远端验收记录" onClick={() => setControl({ action: "accept_hard_capacity", title: "绑定容量验收记录", targets: [{ machine_id: machineId, acceptance_reference: "" }] })}>绑定验收</button>}</div><div className="control-catalog"><button title="允许该机器接受新的 Unit" onClick={() => setControl({ action: "set_admin_mode", title: "管理员开放", targets: [{ machine_id: machineId, requested_mode: "open" }] })}>开放</button><button title="不再接收新 Unit，等待现有任务完成" onClick={() => setControl({ action: "set_admin_mode", title: "管理员排空", targets: [{ machine_id: machineId, requested_mode: "drain" }] })}>排空</button><button title="暂停该机器的新派发和控制操作" onClick={() => setControl({ action: "set_admin_mode", title: "管理员暂停", targets: [{ machine_id: machineId, requested_mode: "paused" }] })}>暂停</button>{policy.admin_mode_override && <button title="移除管理员覆盖，恢复所有者策略" onClick={() => setControl({ action: "clear_admin_mode", title: "清除管理员覆盖", targets: [{ machine_id: machineId }] })}>清除覆盖</button>}<button title="读取进程、心跳和资源状态，不会停止任务" onClick={() => setControl({ action: "health_probe", title: "执行健康检查", targets: [{ machine_id: machineId }] })}>健康检查</button><button title="优雅重启 Supervisor，先保留进行中的 Unit" onClick={() => setControl({ action: "restart_supervisor", title: "重启 supervisor", targets: [{ machine_id: machineId }] })}>重启 supervisor</button><button title="立即重启 Supervisor，仅在优雅重启无法恢复时使用" onClick={() => setControl({ action: "force_restart_supervisor", title: "强制重启 supervisor", targets: [{ machine_id: machineId }] })}>强制重启</button><button title="停止该机器上的 Network attempt，不终止主机其它 COMSOL" onClick={() => setControl({ action: "graceful_stop", title: "优雅终止 Network attempt", targets: [{ machine_id: machineId }] })}>优雅终止</button><button className="danger" title="终止该机器上由 Network 启动的计算，仍保留任务记录" onClick={() => setControl({ action: "emergency_stop_network", title: "Network 紧急停止", targets: [{ machine_id: machineId }] })}>Network 紧急停止</button><button className="danger" title="终止主机上的 COMSOL 进程，可能影响非 Network 任务" onClick={() => setControl({ action: "emergency_stop_host", title: "主机 COMSOL 紧急终止", targets: [{ machine_id: machineId }] })}>主机 COMSOL 终止</button></div></> : <p>当前身份没有管理员控制权限。</p>}</section>}
    {tab === "events" && <section className="detail-section"><header><h2>机器事件</h2><span>{detail.events.length} 条</span></header><div className="audit-table">{detail.events.map((event) => <article key={event.event_id}><time>{time(event.created_at)}</time><b>{event.event_type}</b><span>{event.details?.reason || event.actor_id}</span><code>#{event.sequence}</code></article>)}</div></section>}
    {tab === "config" && <section className="detail-section host-consent-settings"><header><div><h2>管理员主机控制授权</h2><span>只影响非 Network 的外部 COMSOL；Network 自有 Job Object 不受此开关影响</span></div></header><div className={`host-consent ${policy.external_comsol_termination_authorized === false ? "disabled" : "enabled"}`}><AlertTriangle size={17} /><div><b>{policy.external_comsol_termination_authorized === false ? "外部 COMSOL 终止已关闭" : "外部 COMSOL break-glass 已授权"}</b><p>即使授权，管理员仍需完整机器 ID、当前进程集 hash、break-glass PIN 和二次确认。所有操作写入审计。</p></div>{canEditPolicy ? <button className="button" disabled={consentBusy} onClick={() => updateExternalConsent(policy.external_comsol_termination_authorized === false)}>{consentBusy ? "正在保存" : policy.external_comsol_termination_authorized === false ? "重新授权" : "关闭授权"}</button> : <span>机器 owner 或管理员可修改</span>}</div></section>}
{tab === "config" && <><div className="detail-columns"><MachinePolicyEditor machine={machine} policy={policy} policyRevisionHash={detail.policy_revision_hash} config={config} canEdit={canEditPolicy} onSaved={complete} /><ExecutionTuningEditor machine={machine} machineId={machineId} config={config} canEdit={admin} onSaved={complete} /></div><section className="detail-section"><header><div><h2>受控执行状态</h2><span>通过准入、容量验收和 runtime 控制变更</span></div></header><Details rows={Object.entries(config).filter(([key]) => ["enabled", "operational_execution", "conditional_production", "startup_after_reboot", "numeric_equivalence", "supervisor_startup", "tunnel_startup", "runtime_version", "accepted_hard_capacity_units", "hard_capacity_pending_acceptance"].includes(key))} /></section></>}
    {control && <MachineControlDialog {...control} onClose={() => setControl(null)} onComplete={complete} />}
  </main>;
}
