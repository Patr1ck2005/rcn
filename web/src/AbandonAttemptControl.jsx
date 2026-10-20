import { useEffect, useRef, useState } from "react";
import { RefreshCw } from "lucide-react";
import { api, currentIdentityEpoch } from "./api";
import { unitIsReconciling } from "./format";
import { metadataActor, pendingMetadataAction, subscribeMetadataActions } from "./metadataActions";

export function unitCanAbandon(unit) {
  const latest = unit?.attempts?.at(-1);
  return unitIsReconciling(unit)
    && !["completed", "cancelled", "failed_terminal"].includes(unit.status)
    && Boolean(latest?.attempt_id)
    && Number(unit.attempt_count || 0) < Number(unit.max_attempts || 3);
}

export function abandonRequest(jobId, unit, reason) {
  const latest = unit?.attempts?.at(-1);
  if (!jobId || !unitCanAbandon(unit)) throw new Error("当前单元没有可放弃的失联尝试，请刷新状态。");
  if (!reason.trim()) throw new Error("请填写放弃并重算的原因。");
  return {
    job_id: jobId, work_unit_id: unit.work_unit_id,
    machine_id: latest.machine_id || unit.assigned_machine_id || null,
    body: {
      expected_attempt_id: latest.attempt_id,
      expected_external_run_id: latest.external_run_id ?? null,
      reason: reason.trim(),
      operation_id: `admin-abandon-${latest.attempt_id}`,
    },
  };
}

export function abandonmentScope(actorId, jobId, unit) {
  const latest = unit?.attempts?.at(-1);
  return JSON.stringify([actorId || "", jobId, unit?.work_unit_id, latest?.attempt_id, latest?.external_run_id ?? null]);
}

export default function AbandonAttemptControl({ admin = false, jobId, unit, onCompleted }) {
  const [snapshot, setSnapshot] = useState(null);
  const [reason, setReason] = useState("失联机器无法继续对账，管理员决定放弃旧尝试结果并重算原单元。");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [completed, setCompleted] = useState(null);
  const inFlight = useRef(null);
  const submittedBody = useRef(null);
  const [actorId, setActorId] = useState(metadataActor);
  const [identityEpoch, setIdentityEpoch] = useState(currentIdentityEpoch);
  const scope = JSON.stringify([abandonmentScope(actorId, jobId, unit), identityEpoch]);
  const scopeRef = useRef(scope); scopeRef.current = scope;
  const activeSnapshot = snapshot?.scope === scope ? snapshot : null;
  const activeCompleted = completed?.scope === scope ? completed.response : null;
  const matches = (value) => value?.actor_id === metadataActor() && value?.kind === "abandon_attempt"
    && value.subject_id === jobId && value.path === `/v1/admin/jobs/${encodeURIComponent(jobId)}/units/${encodeURIComponent(unit?.work_unit_id)}/abandon-and-retry`;
  const [unknown, setUnknown] = useState(() => matches(pendingMetadataAction(metadataActor())));
  useEffect(() => {
    const update = (event) => {
      setActorId(metadataActor());
      setIdentityEpoch(currentIdentityEpoch());
      setUnknown(matches(pendingMetadataAction(metadataActor())));
      if (scopeRef.current === scope && event?.type === "completed" && matches(event) && event.result?.job_id === jobId
          && event.result?.work_unit_id === unit?.work_unit_id
          && unit?.attempts?.at(-1)?.attempt_id === event.result.abandoned_attempt_id
          && (unit?.attempts?.at(-1)?.external_run_id ?? null) === (event.result.abandoned_external_run_id ?? null)
          && ["queued", "replayed"].includes(event.result.outcome)) {
        setCompleted({ scope, response: event.result }); setSnapshot(null); setError("");
      }
    };
    update(); return subscribeMetadataActions(update);
  }, [jobId, unit, scope]);
  useEffect(() => {
    setSnapshot(null); setCompleted(null); setError(""); setBusy(false); submittedBody.current = null;
    setReason("失联机器无法继续对账，管理员决定放弃旧尝试结果并重算原单元。");
  }, [scope]);
  if (!admin || (!unitCanAbandon(unit) && !activeSnapshot && !activeCompleted && !unknown)) return null;
  const begin = () => {
    if (actorId !== metadataActor() || identityEpoch !== currentIdentityEpoch()) return;
    setError("");
    submittedBody.current = null;
    try { setSnapshot({ ...abandonRequest(jobId, unit, reason), scope }); }
    catch (caught) { setError(caught.message); }
  };
  const confirm = async () => {
    if (actorId !== metadataActor() || identityEpoch !== currentIdentityEpoch() || inFlight.current === scope || unknown || !activeSnapshot || !reason.trim()) return;
    const originalScope = scope;
    inFlight.current = originalScope; setBusy(true); setError("");
    const request = submittedBody.current?.scope === originalScope ? submittedBody.current.body : { ...activeSnapshot.body, reason: reason.trim() };
    submittedBody.current = { scope: originalScope, body: request };
    try {
      const response = await api(`/v1/admin/jobs/${encodeURIComponent(activeSnapshot.job_id)}/units/${encodeURIComponent(activeSnapshot.work_unit_id)}/abandon-and-retry`, {
        method: "POST", body: JSON.stringify(request),
      });
      if (response.job_id !== activeSnapshot.job_id || response.work_unit_id !== activeSnapshot.work_unit_id
          || response.abandoned_attempt_id !== request.expected_attempt_id
          || (response.abandoned_external_run_id ?? null) !== request.expected_external_run_id || !["queued", "replayed"].includes(response.outcome)) {
        throw new Error("没有收到与原尝试匹配的重算回执。");
      }
      if (scopeRef.current !== originalScope) return;
      setCompleted({ scope: originalScope, response }); setSnapshot(null);
      try { await onCompleted?.(response); }
      catch (caught) { if (scopeRef.current === originalScope) setError(`重算已登记，但状态刷新失败：${caught.message}。请刷新页面核对原单元。`); }
    } catch (caught) {
      if (scopeRef.current === originalScope) setError(`${caught.message}。请求仍绑定同一个旧尝试；结果不明时请先核对页面上方的原操作回执。`);
    } finally { if (inFlight.current === originalScope) inFlight.current = null; if (scopeRef.current === originalScope) setBusy(false); }
  };
  return <div className="abandon-attempt-control" style={{ minWidth: 0, maxWidth: "100%", overflowWrap: "anywhere" }}>
    {activeCompleted ? <p role="status">已登记原单元重算，旧尝试结果将被弃用。</p>
      : unknown ? <p role="status">原重算请求的结果待核对，请使用页面上方的“核对原操作”。不会放弃新的计算。</p>
      : activeSnapshot ? <section className="drawer-control" role="dialog" aria-label="放弃旧尝试并重算确认" style={{ marginLeft: 0, marginRight: 0 }}>
        <h3>放弃旧尝试并重算</h3>
        <p>将弃用这个旧尝试已经生成或随后送达的结果，在原 Job 中重新计算同一个单元。此操作不保证远端进程已经停止；短暂断线可以继续等待对账。</p>
        <p>原机器 {activeSnapshot.machine_id || "未知"} · 原尝试 <code>{activeSnapshot.body.expected_attempt_id}</code></p>
        <label>重算原因<input aria-label="放弃并重算原因" value={reason} disabled={busy || submittedBody.current != null} maxLength={500} style={{ minWidth: 0, width: "100%" }} onChange={(event) => setReason(event.target.value)} /></label>
        <div style={{ display: "flex", flexWrap: "wrap", gap: ".4rem", marginTop: ".6rem" }}><button className="button small" disabled={busy} onClick={() => { setSnapshot(null); setError(""); }}>继续等待对账</button><button className="button button-primary small" disabled={busy || !reason.trim()} onClick={confirm}>{busy ? <><RefreshCw className="spin" size={14} />正在登记重算</> : "确认放弃并重算"}</button></div>
      </section> : <button className="button small" disabled={busy} onClick={begin}><RefreshCw size={13} />放弃旧尝试并重算</button>}
    {error && <p className="form-error" role="alert">{error}</p>}
  </div>;
}
