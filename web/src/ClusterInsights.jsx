import { memo, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Activity, ArrowRight, BarChart3, CheckCircle2, Clock3, Gauge, Info, Layers3, RefreshCw, Search, TriangleAlert } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "./api";
import { usePageRefresh } from "./usePageRefresh";
import { DataLoadState } from "./AsyncState";
import { createInsightFollowup, insightSnapshotState } from "./insightRefresh";
import { WORK_STATES, countsTotal, durationText, intervalText, forecastText, numberText, percentText, projectRows, insightScopeLabels } from "./insightFormat";
import "./clusterInsights.css";

function useInsights(hours) {
  const [state, setState] = useState({ data: null, error: "", loading: true });
  const [followupExpired, setFollowupExpired] = useState(false);
  const followup = useRef(null);
  const load = usePageRefresh(async ({ signal, isCurrent }) => {
    setState(s => ({ ...s, loading: true }));
    try {
      const data = await api(`/v1/operations/insights?window_hours=${hours}`, { signal });
      if (isCurrent()) {
        setState({ data, error: "", loading: false });
        followup.current?.observe(data);
      }
    } catch (error) {
      if (isCurrent()) {
        setState(s => ({ ...s, error: error.message, loading: false }));
        followup.current?.fail();
      }
    }
  }, { key: hours, initial: true, resources: ["insights"] });
  useEffect(() => {
    setFollowupExpired(false);
    const controller = createInsightFollowup(load, {
      isVisible: () => document.visibilityState !== "hidden", onExpired: setFollowupExpired,
    });
    followup.current = controller;
    return () => { controller.dispose(); if (followup.current === controller) followup.current = null; };
  }, [hours, load]);
  return { ...state, load, followupExpired };
}

function Stat({ label, value, detail, icon: Icon, tone = "", children }) {
  return <article className={`insight-stat ${tone}`}><div className="insight-stat-label"><Icon size={16} /><span>{label}</span></div>
    <strong>{value}</strong><p>{detail}</p>{children}</article>;
}
function ChartCard({ title, subtitle, children, className = "", accessory }) {
  return <section className={`insight-chart-card ${className}`}><header><div><h2>{title}</h2><p>{subtitle}</p></div>{accessory}</header>{children}</section>;
}
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return <div className="insight-tooltip"><b>{label}</b>{payload.filter(x => x.value != null).map(x => <div key={x.dataKey}><i style={{ background: x.color }} /><span>{x.name}</span><strong>{numberText(x.value)}</strong></div>)}</div>;
}
const timeLabel = value => new Date(value).toLocaleString("zh-CN", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
const snapshotTimeLabel = value => new Date(value).toLocaleString("zh-CN", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const axisTime = (value, hours) => new Date(value).toLocaleString("zh-CN", hours > 24 ? { month: "numeric", day: "numeric" } : { hour: "2-digit", minute: "2-digit", hour12: false });

function Throughput({ group, hours, compact = false }) {
  return <div className="insight-chart" style={{ height: compact ? 130 : 235 }} role="img"
    aria-label={`产出趋势：最近 ${hours} 小时完成 ${group.completed_in_window} 个单元，失败 ${group.failed_attempts} 次尝试`}>
    <ResponsiveContainer width="100%" height="100%"><BarChart data={group.timeline} margin={{ top: 12, right: 10, left: -20, bottom: 0 }} barGap={1}>
      <CartesianGrid vertical={false} stroke="var(--line)" strokeDasharray="3 5" />
      <XAxis dataKey="at" axisLine={false} tickLine={false} tickFormatter={v => axisTime(v, hours)} minTickGap={40} />
      <YAxis allowDecimals={false} axisLine={false} tickLine={false} width={46} />
      <Tooltip content={props => <ChartTooltip {...props} label={timeLabel(props.label)} />} cursor={{ fill: "var(--surface-2)" }} />
      <Bar name="完成单元" dataKey="completed" fill="var(--green)" radius={[3, 3, 0, 0]} isAnimationActive={false} />
      <Bar name="失败尝试" dataKey="failed" fill="var(--amber)" radius={[3, 3, 0, 0]} isAnimationActive={false} />
    </BarChart></ResponsiveContainer>
  </div>;
}
function Workload({ group }) {
  const total = countsTotal(group.counts);
  const data = WORK_STATES.map(s => ({ ...s, value: group.counts[s.key] || 0 }));
  return <div className="insight-workload"><div className="insight-donut" role="img" aria-label={`工作状态分布，总计 ${total} 个单元`}>
    <ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={total ? data : [{ key: "empty", value: 1, color: "var(--surface-3)" }]}
      dataKey="value" innerRadius="69%" outerRadius="91%" paddingAngle={total ? 2 : 0} stroke="none" isAnimationActive={false}>
      {(total ? data : [{ key: "empty", color: "var(--surface-3)" }]).map(s => <Cell key={s.key} fill={s.color} />)}
    </Pie></PieChart></ResponsiveContainer><div className="insight-donut-center"><strong>{numberText(total, 0)}</strong><span>工作单元</span></div>
  </div><dl className="insight-state-legend">{data.map(s => <div key={s.key}><dt><i style={{ background: s.color }} />{s.label}</dt><dd>{numberText(s.value, 0)}</dd></div>)}</dl></div>;
}
function ProjectWorkload({ projects, onSelect }) {
  const top = projects.slice(0, 8).map(p => ({ ...p.counts, project_id: p.project_id }));
  return <div className="insight-chart" style={{ height: Math.max(160, top.length * 40) }} role="img" aria-label="按项目对比已完成、运行、待派发与异常单元">
    {!top.length ? <div className="insight-empty">当前时窗没有项目任务。</div> : <ResponsiveContainer width="100%" height="100%">
      <BarChart data={top} layout="vertical" margin={{ top: 4, right: 12, left: 0, bottom: 0 }}>
        <CartesianGrid horizontal={false} stroke="var(--line)" strokeDasharray="3 5" />
        <XAxis type="number" allowDecimals={false} axisLine={false} tickLine={false} />
        <YAxis type="category" dataKey="project_id" width={145} axisLine={false} tickLine={false} tickFormatter={s => s.length > 20 ? `${s.slice(0, 18)}…` : s} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: "var(--surface-2)" }} />
        {WORK_STATES.map(s => <Bar key={s.key} name={s.label} dataKey={s.key} stackId="work" fill={s.color} barSize={14}
          isAnimationActive={false} onClick={p => { const id = p.project_id || p.payload?.project_id; if (id) onSelect(id); }} cursor="pointer" />)}
      </BarChart>
    </ResponsiveContainer>}
  </div>;
}
function MachineLoad({ machines }) {
  return <div className="insight-machine-list">{machines.slice(0, 12).map(m => {
    const denominator = Math.max(m.effective_slots, m.running_units, 1);
    const width = Math.min(100, 100*m.running_units/denominator);
    return <Link to={`/app/machines/${encodeURIComponent(m.machine_id)}`} key={m.machine_id} className={!m.live ? "is-stale" : ""}>
      <div><b>{m.machine_id}</b><span>{m.live ? `${m.running_units} 运行 / ${m.effective_slots} 有效槽` : "遥测过期 / 不可用"}</span></div>
      <div className="insight-machine-track"><i style={{ width: `${width}%` }} /></div>
      <small>{m.cpu_percent == null ? "CPU 未知" : `CPU ${percentText(m.cpu_percent)}`}<span>{m.eligible ? "开放" : m.reason === "owner_paused" ? "机主暂停" : "当前不可派发"}</span></small>
    </Link>;
  })}{!machines.length && <p className="insight-empty">当前范围暂无机器。</p>}</div>;
}

export default memo(function ClusterInsights({ compact = false, onProjectSelect, selectedProject }) {
  const [params, setParams] = useSearchParams();
  const hours = [1, 6, 24, 168].includes(Number(params.get("window"))) ? Number(params.get("window")) : 24;
  const chosen = selectedProject ?? (params.get("project") || "");
  const { data, loading, error, load, followupExpired } = useInsights(hours);
  const [search, setSearch] = useState("");
  const selectProject = id => {
    if (onProjectSelect) onProjectSelect(id);
    else { const next = new URLSearchParams(params); id ? next.set("project", id) : next.delete("project"); setParams(next); }
  };
  const changeWindow = hours => { const next = new URLSearchParams(params); next.set("window", String(hours)); setParams(next); };
  const goodData = data && data.window_hours === hours;
  if (!goodData) return <div className="insights-panel"><DataLoadState label="正在汇总集群工作状态" error={error} onRetry={load} /></div>;
  const group = chosen ? data.projects.find(p => p.project_id === chosen) : data.overall;
  const freshness = insightSnapshotState(data, error, { followupExpired });
  const { stale } = freshness;
  const incomplete = data.source?.source_truncated || data.source?.missing_or_oversized_projections || data.source?.malformed_records;
  const stats = group || data.overall;
  const forecast = forecastText(group?.forecast, stale);
  const scopeLabels = insightScopeLabels(data);
  const title = chosen || scopeLabels.title;
  const total = countsTotal(stats.counts);
  const projectOptions = data.projects || [];
  return <section className={`insights-panel ${compact ? "is-compact" : ""}`} aria-label="集群效能总览">
    <header className="insight-topbar"><div><span className="insight-eyebrow"><Activity size={14} />COMPUTE / INSIGHTS{data.dataset_mode === "demo" && <b className="insight-demo-badge">演示数据 · 非实机</b>}</span><h1>{compact ? "集群工作摘要" : title}</h1><p>当前队列 · 算力投入 · 实际产出{scopeLabels.filtered ? " · 已按当前身份过滤" : ""}</p></div>
      <div className="insight-controls"><label><span className="sr-only">按项目筛选</span><select aria-label="按项目筛选" value={chosen} onChange={e => selectProject(e.target.value)}>
        <option value="">{scopeLabels.projects}</option>{projectOptions.map(p => <option key={p.project_id} value={p.project_id}>{p.project_id}</option>)}
        {chosen && !group && <option value={chosen}>{chosen}（当前范围无数据）</option>}
      </select></label><div className="insight-period" aria-label="统计时窗">{[[1, "1 小时"], [6, "6 小时"], [24, "24 小时"], [168, "7 天"]].map(([value, label]) => <button key={value} aria-pressed={hours === value} onClick={() => changeWindow(value)}>{label}</button>)}</div>
      <button className="icon-button" title="刷新效能数据" onClick={load} disabled={loading}><RefreshCw size={16} className={loading ? "spin" : ""} /></button></div>
    </header>
    {(stale || incomplete || !group || data.projects_truncated) && <div className="insight-warning" role="status"><TriangleAlert size={16} /><span>{stale ? freshness.message : incomplete ? "读模型不完整或达到安全上限；显示已知部分，不承诺整体完工时间。" : !group ? "此项目在当前权限或统计时窗中没有数据；以下为可见总体，不代表该项目。" : "项目列表达到展示上限；全局统计仍包含已读取项目。"}{stale && <small>上次快照 {snapshotTimeLabel(data.generated_at)}</small>}{freshness.error && <small>{freshness.error}</small>}</span></div>}
    {data.capacity.over_capacity_slots > 0 && <div className="insight-warning" role="status"><TriangleAlert size={16} />现有运行槽超过当前有效上限 {data.capacity.over_capacity_slots} 个，可能正在排空或降容；不截断百分比，也不新增派发承诺。</div>}
    <div className="insight-stat-grid">
      <Stat label={incomplete ? "已知工作量（数据不全）" : "当前工作量"} icon={Layers3} value={`${numberText(stats.active_jobs, 0)} 个 Job`} detail={`${numberText(stats.counts.running, 0)} 运行 · ${numberText(stats.counts.waiting, 0)} 待派发 · ${numberText(stats.counts.collecting + stats.counts.attention, 0)} 回收或异常`}>
        <div className="insight-mini-stack" aria-label={`共 ${total} 个单元`}>{WORK_STATES.map(s => <i key={s.key} style={{ width: `${total ? stats.counts[s.key] / total * 100 : 0}%`, background: s.color }} title={`${s.label} ${stats.counts[s.key]}`} />)}</div>
      </Stat>
      <Stat label={chosen ? "项目产出速率" : "并发利用率"} icon={Gauge}
        value={chosen ? `${numberText(stats.throughput_units_per_hour)} / 小时` : percentText(data.capacity.utilization_percent)}
        detail={chosen ? `最近 ${hours} 小时完成 ${numberText(stats.completed_in_window, 0)} 个单元` : `${data.capacity.running_slots} 运行 / ${data.capacity.effective_slots} 当前有效槽 · 非 CPU 使用率`} tone="accent" />
      <Stat label="有效执行占比" icon={CheckCircle2} value={percentText(stats.effective_execution_percent)} detail={stats.terminal_attempts ? `已结束尝试的成功核时占比 · 计时覆盖 ${percentText(stats.timing_coverage_percent)}` : "尚无已结束尝试的计时证据"} tone="success" />
      <Stat label="当前队列预计还需" icon={Clock3} value={forecast.value} detail={forecast.detail}>
        {!stale && group?.forecast?.seconds > 0 && <small className="insight-eta-range">样本 {group.forecast.sample_count || 0} · {group.forecast.confidence === "medium" ? "历史估计" : "初步估计"}<br />情景范围 {durationText(group.forecast.lower_seconds)} – {durationText(group.forecast.upper_seconds)}{group.forecast.finish_at && <span>预计 {timeLabel(group.forecast.finish_at)}</span>}</small>}
      </Stat>
    </div>
    {compact ? <div className="insight-compact-foot"><span><i />近 {hours} 小时：{stats.completed_in_window} 单元完成 · 未产出核时 {numberText(stats.unproductive_core_hours)} h</span><Link to={`/app/overview?window=${hours}${chosen ? `&project=${encodeURIComponent(chosen)}` : ""}`}>查看完整图表<ArrowRight size={15} /></Link></div> : <>
      <div className="insight-chart-grid primary"><ChartCard title="产出趋势" subtitle={`完成按回收时间计数 · 每格 ${intervalText(data.bin_seconds)} · 不同单元工作量可不同`} accessory={<div className="insight-rate"><strong>{numberText(stats.throughput_units_per_hour)}</strong><span>单元 / 小时</span></div>}><Throughput group={stats} hours={hours} /><div className="insight-inline-legend"><span><i className="completed" />完成单元</span><span><i className="failed" />失败尝试</span></div></ChartCard>
        <ChartCard title="工作状态" subtitle="当前任务及本时窗结束的任务"><Workload group={stats} /></ChartCard></div>
      <div className="insight-chart-grid secondary"><ChartCard title="项目工作量对比" subtitle="当前可见范围前 8 个项目 · 点击图形可筛选"><ProjectWorkload projects={data.projects} onSelect={selectProject} /><div className="insight-inline-legend">{WORK_STATES.map(s => <span key={s.key}><i style={{ background: s.color }} />{s.label}</span>)}</div></ChartCard>
        <ChartCard title="机器当前负载" subtitle="运行槽与有效槽 · CPU 是辅助遥测"><MachineLoad machines={data.machines} /></ChartCard></div>
      <section className="insight-project-table"><header><div><h2>项目进度与完工预测</h2><p>当前可见项目并行计算，取最晚预计完工时间。</p></div><label className="search"><Search size={15} /><input aria-label="搜索效能项目" placeholder="搜索项目" value={search} onChange={e => setSearch(e.target.value)} /></label></header>
        <div className="table-wrap"><table><thead><tr><th>项目</th><th>工作进度</th><th>活动 Job</th><th>完成 / 小时</th><th>有效执行占比</th><th>预计还需</th><th /></tr></thead><tbody>{projectRows(data, search).map(p => {
          const f = forecastText(p.forecast, stale); return <tr key={p.project_id} className={p.project_id === chosen ? "is-selected" : ""}>
            <th><button className="insight-project-link" onClick={() => selectProject(p.project_id)}>{p.project_id}</button></th>
            <td><div className="insight-progress-track"><i style={{ width: `${p.completion_percent || 0}%` }} /></div><small>{p.counts.completed} / {countsTotal(p.counts)} 单元</small></td>
            <td>{p.active_jobs}</td><td>{numberText(p.throughput_units_per_hour)}</td><td>{percentText(p.effective_execution_percent)}</td>
            <td className="insight-table-eta"><b>{f.value}</b><small>{f.detail}</small></td>
            <td><Link title={`查看 ${p.project_id} 的任务`} to={`/app/runs?project=${encodeURIComponent(p.project_id)}&window=${hours}`}><ArrowRight size={17} /></Link></td>
          </tr>;
        })}</tbody></table>{!projectRows(data, search).length && <p className="insight-empty">当前筛选没有项目记录。</p>}</div>
      </section>
    </>}
    <footer className="insight-footnote"><span><Activity size={13} />快照 <time dateTime={data.generated_at}>{snapshotTimeLabel(data.generated_at)}</time> · {data.source?.jobs_scanned ?? "—"} 个读模型 · {scopeLabels.tasks}</span>
      <details><summary><Info size={14} />指标口径与估计边界</summary><dl>{Object.entries(data.definitions || {}).map(([key, value]) => <div key={key}><dt>{{ efficiency:"有效执行占比", throughput:"产出速率", utilization:"并发利用率", forecast:"预计完工" }[key]}</dt><dd>{value}</dd></div>)}</dl><p>已排除 {data.source?.excluded_nonproduction_jobs || 0} 个验收等非生产 Job；总状态包含当前任务和时窗内结束的任务，产出曲线只计时窗内完成事件。</p></details>
    </footer>
  </section>;
});
