import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, CheckCircle2, RefreshCw, RotateCcw, ShieldAlert } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { api } from "./api";
import { usePageRefresh } from "./usePageRefresh";
import { DataLoadState, RefreshStatus } from "./AsyncState";
import { MachineControlDialog, RuntimeControlDialog } from "./ControlDialogs";

const terminal = new Set(["completed", "partial_failed", "failed"]);
const time = (value) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "-";

export default function ControlOperationDetail() {
  const { operationId } = useParams();
  const [run, setRun] = useState(null);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(false);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState(null);
  const load = usePageRefresh(async ({ signal, isCurrent }) => {
    setLoading(true);
    try {
      const next = await api(`/v1/admin/control-runs/${encodeURIComponent(operationId)}`, { signal });
      if (next?.operation_id !== operationId) throw new Error("控制操作响应与当前操作不匹配");
      if (isCurrent()) { setRun(next); setUpdatedAt(new Date().toISOString()); setError(""); }
    } catch (caught) { if (isCurrent()) setError(caught.message); }
    finally { if (isCurrent()) setLoading(false); }
  }, { key: operationId, initial: true, intervalMs: !run || !terminal.has(run.state) ? 3000 : 0, resources: ["control-runs"] });
  useEffect(() => { setRun(null); setRetry(false); setError(""); setUpdatedAt(null); }, [operationId]);
  const failed = useMemo(() => run?.targets?.filter((target) => target.state === "failed") || [], [run]);
  const failedIds = new Set(failed.map((target) => target.machine_id));
  const retryTargets = (run?.request_targets || []).filter((target) => failedIds.has(target.machine_id));
  const runtimeAction = ["promote_runtime", "rollback_runtime"].includes(run?.action);
  const canRetry = failed.length > 0 && (runtimeAction || retryTargets.length === failed.length);
  if (!run && (loading || error)) return <main className="app-page"><DataLoadState label="正在读取控制操作" error={error} onRetry={load} /></main>;
  return <main className="app-page"><div className="page-title"><div><span>CONTROL / OPERATION</span><h1>控制操作详情</h1><p>{operationId} · 最近成功读取 {time(updatedAt)}</p></div><div className="page-actions"><Link className="button" to="/app/control"><ArrowLeft size={16} />返回控制中心</Link><RefreshStatus visible={loading} /><button className="button" disabled={loading} onClick={load}><RefreshCw size={16} />刷新</button></div></div>
    {error && <div className="inline-error">刷新失败：{error}</div>}
    {run && <><section className="control-dashboard"><article><CheckCircle2 size={18} /><div><span>当前阶段</span><strong>{run.state}</strong></div></article><article><ShieldAlert size={18} /><div><span>操作</span><strong>{run.action}</strong></div></article><article><RefreshCw size={18} /><div><span>目标</span><strong>{run.targets.length}</strong></div></article><article><RotateCcw size={18} /><div><span>失败</span><strong>{failed.length}</strong></div></article></section>
      <section className="detail-section operation-detail"><header><div><h2>真实执行阶段</h2><span>preview → accepted → remote acknowledged → final</span></div><span className={`status status-${run.state}`}>{run.state}</span></header><div className="operation-stages"><span className="done">preview</span><span className="done">accepted</span><span className={["remote_acknowledged", ...terminal].includes(run.state) ? "done" : ""}>remote acknowledged</span><span className={terminal.has(run.state) ? "done" : ""}>final</span></div><dl className="detail-grid"><div><dt>票据</dt><dd>{run.ticket_id}</dd></div><div><dt>发起人</dt><dd>{run.requested_by}</dd></div><div><dt>原因</dt><dd>{run.reason || "未填写"}</dd></div><div><dt>创建</dt><dd>{time(run.created_at)}</dd></div><div><dt>更新</dt><dd>{time(run.updated_at)}</dd></div></dl>{canRetry && <button className="button" onClick={() => setRetry(true)}><RotateCcw size={15} />仅重试失败目标</button>}</section>
      <section className="detail-section"><header><div><h2>逐机结果</h2><span>已成功目标不会回滚</span></div></header><div className="target-results detailed">{run.targets.map((target) => { const impact = run.impact?.[target.machine_id] || {}; return <article key={target.machine_id}><header><Link to={`/app/machines/${target.machine_id}`}><b>{target.machine_id}</b></Link><span className={`status status-${target.state}`}>{target.state}</span></header><p>{target.message || "等待远端结果"}</p><dl><div><dt>command</dt><dd>{target.command_id || "本地控制"}</dd></div>{impact.running_runtime_version && <div><dt>运行时</dt><dd>{impact.running_runtime_version} → {impact.target_runtime_version}</dd></div>}<div><dt>更新时间</dt><dd>{time(target.updated_at)}</dd></div></dl></article>; })}</div></section>
    </>}
    {retry && runtimeAction && failed[0] && <RuntimeControlDialog machineId={failed[0].machine_id} action={run.action} onClose={() => setRetry(false)} onComplete={load} />}
    {retry && !runtimeAction && <MachineControlDialog action={run.action} targets={retryTargets} title="仅重试失败目标" onClose={() => setRetry(false)} onComplete={load} />}
  </main>;
}
