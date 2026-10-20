import { useState } from "react";
import { usePageRefresh } from "./usePageRefresh";
import { Activity, CheckCircle2, CircleStop, Gauge, Play, RefreshCw, RotateCcw, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";

import { api } from "./api";
import { DataLoadState, RefreshStatus } from "./AsyncState";
import { DispatcherControlDialog } from "./ControlDialogs";
import { HelpLink } from "./HelpSystem";
import SchedulingControls from "./SchedulingControls";
import DistributionStatus from "./DistributionStatus";

const labels = { accepted: "服务端已接受", remote_acknowledged: "远端已确认", completed: "已完成", partial_failed: "部分失败", failed: "失败" };
const time = (value) => value ? new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(new Date(value)) : "-";

export const dispatcherActionAvailability = (snapshot = {}) => {
  const running = Boolean(snapshot.running);
  const drained = snapshot.control_mode === "drain";
  const processUnverified = !running && Boolean(
    snapshot.lease_owner || snapshot.phase === "active" || snapshot.accepting_assignments,
  );
  const unavailableReason = processUnverified
    ? "数据库仍显示 Dispatcher 活动，但进程指纹尚未确认；请刷新或执行状态对账"
    : "";
  return {
    start: { enabled: !running && !processUnverified, reason: running ? "Dispatcher 已在运行" : unavailableReason },
    drain: { enabled: running && !drained, reason: !running ? "Dispatcher 当前未运行" : drained ? "Dispatcher 已处于排空状态" : "" },
    stop: { enabled: running, reason: running ? "" : "Dispatcher 当前未运行" },
    restart: { enabled: running, reason: running ? "" : "Dispatcher 当前未运行" },
    reconcile: { enabled: !running && !processUnverified, reason: running ? "请先停止 Dispatcher，再单独执行 reconcile" : unavailableReason },
    force_stop: { enabled: running, reason: running ? "" : "Dispatcher 当前未运行" },
  };
};

export const dispatcherDisplayState = (snapshot = {}) => {
  const running = Boolean(snapshot.running);
  const hasActivity = Boolean(
    snapshot.lease_owner || snapshot.phase === "active" || snapshot.accepting_assignments,
  );
  if (!running && hasActivity) {
    return {
      key: "uncertain",
      label: "状态校验中",
      detail: "数据库显示活动，但进程指纹尚未确认",
    };
  }
  if (!running) {
    return { key: "stopped", label: "已停止", detail: "无活动进程或调度租约" };
  }
  if (snapshot.control_mode === "drain" || !snapshot.accepting_assignments) {
    return { key: "drain", label: "运行中 · 排空", detail: "不接收新派发，等待在途任务完成" };
  }
  return { key: "running", label: "运行中 · 接收派发", detail: "进程指纹与调度租约已确认" };
};

export default function ControlCenter({ onGlobalRefresh }) {
  const [runs, setRuns] = useState([]);
  const [dispatcher, setDispatcher] = useState(null);
  const [dialog, setDialog] = useState(null);
  const [loaded, setLoaded] = useState(false);
  const [loading, setLoading] = useState(true);
  const [requests, setRequests] = useState({});
  const load = usePageRefresh(async ({ signal, isCurrent }) => {
    setLoading(true);
    await Promise.allSettled([
      ["runs", "/v1/admin/control-runs?limit=200", setRuns],
      ["dispatcher", "/v1/dispatcher/status", setDispatcher],
    ].map(async ([key, path, commit]) => {
      try {
        const value = await api(path, { signal });
        if (!isCurrent()) return;
        commit(value); setLoaded(true);
        setRequests((current) => ({ ...current, [key]: { updatedAt: new Date().toISOString(), error: "" } }));
      } catch (caught) {
        if (isCurrent()) setRequests((current) => ({ ...current, [key]: { ...current[key], error: caught.message } }));
      }
    }));
    if (isCurrent()) setLoading(false);
  }, { initial: true, intervalMs: 5000, resources: ["control-runs", "dispatcher"] });
  const readErrors = Object.entries(requests).filter(([, state]) => state.error).map(([key, state]) => `${key === "runs" ? "操作记录" : "Dispatcher"}：${state.error}`).join("；");
  const snapshot = dispatcher?.process || {};
  const availability = dispatcherActionAvailability(snapshot);
  const displayState = dispatcher ? dispatcherDisplayState(snapshot)
    : { key: "uncertain", label: "状态未读取", detail: "尚未成功读取 Dispatcher 状态" };
  const complete = async () => { await load(); await onGlobalRefresh?.(); };
  if (!loaded && (loading || readErrors)) return <main className="app-page"><div className="page-title"><div><span>CONTROL / OPERATIONS</span><h1>控制中心</h1><p>批量票据、远端执行阶段、失败子项和固定 Dispatcher 控制器</p></div></div><DataLoadState label="正在加载控制状态" error={readErrors} onRetry={load} /></main>;
  return <main className="app-page"><div className="page-title"><div><span>CONTROL / OPERATIONS</span><h1>控制中心</h1><p>批量票据、远端执行阶段、失败子项和固定 Dispatcher 控制器</p></div><div className="page-actions"><HelpLink topic="dispatcher" /><RefreshStatus visible={loading} /><button className="button" disabled={loading} onClick={load}><RefreshCw size={16} />刷新</button></div></div>{readErrors && <div className="inline-error">刷新失败：{readErrors}。上次成功内容仍保留。</div>}
    <section className="control-dashboard"><article><Activity size={18} /><div><span>活动操作</span><strong>{runs.filter((run) => ["accepted", "remote_acknowledged"].includes(run.state)).length}</strong></div></article><article><ShieldAlert size={18} /><div><span>部分失败</span><strong>{runs.filter((run) => run.state === "partial_failed").length}</strong></div></article><article><Gauge size={18} /><div><span>Dispatcher</span><strong className={`dispatcher-summary-${displayState.key}`}>{displayState.label}</strong></div></article><article><CheckCircle2 size={18} /><div><span>待 reconcile</span><strong>{snapshot.pending_reconciliation || 0}</strong></div></article></section>
    <section className="detail-section dispatcher-control"><header><div><h2>Dispatcher</h2><span>固定解释器、数据库和参数</span></div><div className={`dispatcher-state dispatcher-state-${displayState.key}`}><b>{displayState.label}</b><small>{displayState.detail}</small><small>更新 {time(requests.dispatcher?.updatedAt)}</small><small>{snapshot.control_mode || "unknown"} · lease {snapshot.lease_owner || "none"}</small></div></header><div className="control-catalog"><button disabled={!dispatcher || !availability.start.enabled} title={availability.start.reason || "启动 Dispatcher"} onClick={() => setDialog("start")}><Play size={15} />启动</button><button disabled={!dispatcher || !availability.drain.enabled} title={availability.drain.reason || "停止接受新派发，继续完成现有任务"} onClick={() => setDialog("drain")}><Gauge size={15} />排空</button><button disabled={!dispatcher || !availability.stop.enabled} title={availability.stop.reason || "协作停止 Dispatcher"} onClick={() => setDialog("stop")}><CircleStop size={15} />停止</button><button disabled={!dispatcher || !availability.restart.enabled} title={availability.restart.reason || "停止并重新启动 Dispatcher"} onClick={() => setDialog("restart")}><RotateCcw size={15} />重启</button><button disabled={!dispatcher || !availability.reconcile.enabled} title={availability.reconcile.reason || "仅执行恢复核对，不启动持续派发"} onClick={() => setDialog("reconcile")}><RefreshCw size={15} />仅 reconcile</button><button className="danger" disabled={!dispatcher || !availability.force_stop.enabled} title={availability.force_stop.reason || "立即终止 Dispatcher 进程"} onClick={() => setDialog("force_stop")}><ShieldAlert size={15} />强制停止</button></div></section>
    <SchedulingControls />
    <DistributionStatus />
    <section className="detail-section"><header><div><h2>控制操作</h2><span>{runs.length} 条最近记录 · 更新 {time(requests.runs?.updatedAt)}</span></div></header><div className="control-run-list">{runs.map((run) => <article key={run.operation_id}><header><div><b>{run.action}</b><code>{run.operation_id}</code></div><span className={`status status-${run.state}`}>{labels[run.state] || run.state}</span></header><div className="operation-stages"><span className="done">preview</span><span className="done">accepted</span><span className={["remote_acknowledged", "completed", "partial_failed", "failed"].includes(run.state) ? "done" : ""}>remote acknowledged</span><span className={["completed", "partial_failed", "failed"].includes(run.state) ? "done" : ""}>final</span></div><div className="target-results">{run.targets.map((target) => <div key={target.machine_id}><b>{target.machine_id}</b><span>{target.state}</span><small>{target.message}</small></div>)}</div><footer><span>{run.requested_by}</span><time>{time(run.updated_at)}</time><Link className="button small" to={`/app/control/${run.operation_id}`}>查看详情</Link></footer></article>)}{!runs.length && <p className="empty compact">尚无控制操作。</p>}</div></section>
    {dialog && <DispatcherControlDialog action={dialog} snapshot={snapshot} onClose={() => setDialog(null)} onComplete={complete} />}
  </main>;
}
