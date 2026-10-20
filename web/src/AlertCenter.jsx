import { useMutationGuard } from "./useMutationGuard";
import { useEffect, useRef, useState } from "react";
import { AlertTriangle, BellRing, CheckCircle2, Clock3, RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";

import { api } from "./api";
import { usePageRefresh } from "./usePageRefresh";
import { DataLoadState, RefreshStatus } from "./AsyncState";
import { alertTransitionCheckpoint, clearAlertTransition, loadAlertTransitions, recoverAlertTransition, saveAlertTransition } from "./alertTransitionCheckpoint";

const time = (value) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "-";

export default function AlertCenter() {
  const [alerts, setAlerts] = useState([]);
  const mutation = useMutationGuard();
  const [showResolved, setShowResolved] = useState(false);
  const [error, setError] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [loading, setLoading] = useState(true);
  const [actorId, setActorId] = useState("");
  const [actorReady, setActorReady] = useState(false);
  const [identityRetry, setIdentityRetry] = useState(0);
  const [pending, setPending] = useState({});
  const [notice, setNotice] = useState("");
  const alive = useRef(true), currentActor = useRef("");
  useEffect(() => {
    alive.current = true; let current = true; const controller = new AbortController();
    setActorReady(false); setLoading(true);
    (async () => {
      try {
        const me = await api("/v1/me", { signal: controller.signal });
        if (!current) return;
        if (!me?.actor_id) throw new Error("尚未读取操作者身份。");
        currentActor.current = me.actor_id; setActorId(me.actor_id);
        let values = loadAlertTransitions(sessionStorage, me.actor_id); setPending(values);
        // Identity and original receipts are checked before the initial list.
        for (const value of Object.values(values)) {
          try {
            await recoverAlertTransition(api, value);
            if (!current) return;
            values = clearAlertTransition(sessionStorage, value); setPending(values);
            setNotice("原告警操作已核对，正在读取当前列表。");
          } catch (caught) { if (current) setNotice(`原告警操作结果待核对：${caught.message}。不会自动重复提交。`); }
        }
        if (current) setActorReady(true);
      } catch (caught) { if (current) { setError(caught.message); setLoading(false); } }
    })();
    return () => { current = false; alive.current = false; controller.abort(); };
  }, [identityRetry]);
  const load = usePageRefresh(async ({ signal, isCurrent }) => {
    setLoading(true);
    try {
      const value = await api(`/v1/admin/alerts?include_resolved=${showResolved}`, { signal });
      if (isCurrent()) { setAlerts(value); setLoaded(true); setError(""); }
    } catch (caught) { if (isCurrent()) setError(caught.message); }
    finally { if (isCurrent()) setLoading(false); }
  }, { key: showResolved, initial: true, enabled: actorReady, resources: ["alerts"] });
  const finish = async (value) => {
    if (!alive.current || currentActor.current !== value.actor_id) return;
    await load();
    if (!alive.current || currentActor.current !== value.actor_id) return;
    setPending(clearAlertTransition(sessionStorage, value)); setNotice("原告警操作已核对，当前列表已刷新。");
  };
  const recover = (value) => mutation.run(async () => {
    setError("");
    try {
      await recoverAlertTransition(api, value); await finish(value);
    } catch (caught) { if (alive.current) setError(`原告警操作结果待核对：${caught.message}。原请求已保留。`); }
  });
  const transition = (alert, status, hours = 0, original = null) => mutation.run(async () => {
    let value = original;
    let stored = Boolean(original);
    setError(""); setNotice("");
    try {
      if (!actorReady || !actorId) throw new Error("请先读取操作者身份。");
      if (!value && pending[alert.alert_id]) throw new Error("请先核对该告警的原操作。");
      value ||= alertTransitionCheckpoint(actorId, alert, status, hours);
      if (value.actor_id !== actorId || value.conflict) throw new Error("原告警操作与当前身份或版本冲突，需先核对。");
      setPending(saveAlertTransition(sessionStorage, value));
      stored = true;
      const result = await api(`/v1/admin/alerts/${encodeURIComponent(value.alert_id)}/transition`, { method: "POST", body: JSON.stringify(value.body) });
      if (result?.alert_id !== value.alert_id) throw new Error("告警响应与原目标不匹配。");
      await finish(value);
    } catch (caught) {
      if (!value || !stored || !alive.current) { if (alive.current) setError(caught.message); return; }
      try { await recoverAlertTransition(api, value); await finish(value); }
      catch {
        if (caught.status === 409) {
          const conflicted = { ...value, conflict: true }; setPending(saveAlertTransition(sessionStorage, conflicted));
          await load(); setError("原告警已变化，原操作未确认。已刷新当前状态；请核对后结束原操作，不会自动创建新意图。");
        } else setError(`告警操作结果待核对：${caught.message}。原请求和绝对暂缓期限已保留。`);
      }
    }
  });
  const retryLoad = () => actorReady ? load() : setIdentityRetry((value) => value + 1);
  return <main className="app-page"><div className="page-title"><div><span>ALERTS / AUDITABLE</span><h1>告警中心</h1><p>确认、限时暂缓、解决状态和关联对象下钻</p></div><div className="page-actions"><label className="toggle"><input type="checkbox" checked={showResolved} onChange={(event) => setShowResolved(event.target.checked)} />显示已解决</label><RefreshStatus visible={loading && loaded} /><button className="button" disabled={loading} onClick={load}><RefreshCw size={16} />刷新</button></div></div>
    {notice && <p role="status">{notice}</p>}
    {actorReady && Object.values(pending).map((value) => <section className="notice" key={value.alert_id}><div><b>原告警操作待核对：{value.alert_id}</b><p>目标 {value.body.status}{value.body.snoozed_until ? ` · 原暂缓至 ${time(value.body.snoozed_until)}` : ""}</p><button className="button small" disabled={mutation.busy} onClick={() => recover(value)}>核对原告警操作</button>{value.conflict ? <button className="button small" disabled={mutation.busy} onClick={() => { setPending(clearAlertTransition(sessionStorage, value)); setNotice("已结束冲突的原操作，请按当前告警状态重新选择。"); }}>已核对，结束原操作</button> : <button className="button small" disabled={mutation.busy} onClick={() => transition(null, null, 0, value)}>重试原告警操作</button>}</div></section>)}
    {!actorReady || (!loaded && (loading || error)) ? <DataLoadState label="正在加载告警" error={error} onRetry={retryLoad} /> : <><section className="alert-board">{alerts.map((alert) => <article className={`alert-record severity-${alert.severity}`} key={alert.alert_id}><header><div>{alert.severity === "critical" ? <AlertTriangle size={18} /> : <BellRing size={18} />}<span><b>{alert.message}</b><small>{alert.kind} · {alert.subject_type}</small></span></div><span className={`status status-${alert.status}`}>{alert.status}</span></header><p>{alert.reason || "无附加原因"}</p><dl><div><dt>首次发生</dt><dd>{time(alert.first_seen_at)}</dd></div><div><dt>最近发生</dt><dd>{time(alert.last_seen_at)}</dd></div><div><dt>次数</dt><dd>{alert.occurrence_count}</dd></div><div><dt>关联对象</dt><dd>{alert.subject_id}</dd></div></dl><footer><Link className="button small" to={alert.subject_type === "machine" ? `/app/machines/${alert.subject_id}` : `/app/runs/${alert.subject_id}`}>查看详情</Link>{alert.status === "active" && <button className="button small" disabled={mutation.busy || Boolean(pending[alert.alert_id])} onClick={() => transition(alert, "acknowledged")}><CheckCircle2 size={14} />确认</button>}{!["resolved"].includes(alert.status) && <button className="button small" disabled={mutation.busy || Boolean(pending[alert.alert_id])} onClick={() => transition(alert, "snoozed", 1)}><Clock3 size={14} />暂缓 1h</button>}{alert.status !== "resolved" && <button className="button small" disabled={mutation.busy || Boolean(pending[alert.alert_id])} onClick={() => transition(alert, "resolved")}>标记解决</button>}</footer></article>)}{!alerts.length && <div className="empty"><CheckCircle2 size={20} />当前没有告警</div>}</section>{error && <div className="inline-error">操作或读取失败：{error}</div>}</>}
  </main>;
}
