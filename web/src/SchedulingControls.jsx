import { useEffect, useRef, useState } from "react";
import { api, currentIdentityEpoch } from "./api";
import { metadataActor, pendingMetadataAction, subscribeMetadataActions } from "./metadataActions";
import { useMutationGuard } from "./useMutationGuard";
import { DataLoadState } from "./AsyncState";
import "./schedulingControls.css";

export const strategies = [
  ["balanced", "公平均衡", "按近期项目与成员使用量分配，兼顾等待时间。"],
  ["small_batch_first", "小批量优先", "同等优先级与项目份额下，优先预计可较快完成的剩余工作。"],
  ["throughput", "吞吐优先", "优先可较快完成的工作；同类实测足够时参考机器性能。"],
];

export function policyChange(snapshot, draft, reason) {
  if (!snapshot || !draft || !reason.trim()) throw new Error("请填写变更原因");
  if (parallelBatchEnabled(draft) && (!Number.isInteger(draft.small_batch_max_parallel_seconds)
      || draft.small_batch_max_parallel_seconds < 60 || draft.small_batch_max_parallel_seconds > 86400)) {
    throw new Error("并行完工上限须为 1–1440 分钟，且精确到整秒");
  }
  return { expected_revision: snapshot.revision, policy: { ...draft }, reason: reason.trim() };
}

export function supportsParallelBatch(snapshot) {
  return snapshot?.parallel_small_batch_schema === 1
    || Object.prototype.hasOwnProperty.call(snapshot?.policy || {}, "small_batch_max_parallel_seconds");
}

export function parallelBatchEnabled(policy) {
  return policy?.small_batch_max_parallel_seconds != null;
}

export function smallBatchThresholdText(policy) {
  return parallelBatchEnabled(policy)
    ? `并行完工上限 ${policy.small_batch_max_parallel_seconds / 60} 分钟（最大兼容容量）`
    : `小批量阈值 ${policy.small_batch_max_units} 单元 / 总串行 ${policy.small_batch_max_serial_seconds} 秒`;
}

export function SmallBatchLimits({ draft, onChange, disabled, supportsParallel }) {
  const parallel = parallelBatchEnabled(draft);
  return <div className="scheduling-limits">
    {supportsParallel && <label>小批量判定方式<select aria-label="小批量判定方式" value={parallel ? "parallel" : "legacy"} disabled={disabled}
      onChange={event => onChange({ ...draft, small_batch_max_parallel_seconds: event.target.value === "parallel" ? 2460 : null })}>
      <option value="parallel">最大兼容容量下的并行完工时间</option>
      <option value="legacy">旧版单元数与串行时长</option>
    </select></label>}
    {parallel ? <label>小批量并行完工上限（分钟）<input type="number" min="1" max="1440" step="any"
      value={draft.small_batch_max_parallel_seconds / 60} disabled={disabled}
      onChange={event => onChange({ ...draft, small_batch_max_parallel_seconds: Number(event.target.value) * 60 })} /></label> : <>
      <label>小批量最多单元数<input type="number" min="1" max="128" value={draft.small_batch_max_units}
        disabled={disabled} onChange={event => onChange({ ...draft, small_batch_max_units: Number(event.target.value) })} /></label>
      <label>小批量总预计时长上限（秒）<input type="number" min="60" max="86400" value={draft.small_batch_max_serial_seconds}
        disabled={disabled} onChange={event => onChange({ ...draft, small_batch_max_serial_seconds: Number(event.target.value) })} /></label>
    </>}
    <label>未获派发多久后提升优先级（秒）<input type="number" min="60" max="86400" value={draft.starvation_after_s}
      disabled={disabled} onChange={event => onChange({ ...draft, starvation_after_s: Number(event.target.value) })} /></label>
  </div>;
}

export default function SchedulingControls() {
  const [snapshot, setSnapshot] = useState(null);
  const [draft, setDraft] = useState(null);
  const [reason, setReason] = useState("");
  const [pending, setPending] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [waiting, setWaiting] = useState(false);
  const submitted = useRef(null);
  const snapshotRef = useRef(snapshot); snapshotRef.current = snapshot;
  const draftRef = useRef(draft); draftRef.current = draft;
  const mounted = useRef(false);
  const mutation = useMutationGuard();
  const load = async (preserveDraft = false) => {
    try {
      const value = await api("/v1/settings/scheduling");
      if (mounted.current) {
        const before = snapshotRef.current;
        if (preserveDraft && before && JSON.stringify(draftRef.current) !== JSON.stringify(before.policy)) {
          if (value.revision !== before.revision) setNotice(`中心当前修订为 ${value.revision}；保留原版本草稿，请核对后再变更。`);
          return;
        }
        setSnapshot(value);
        setDraft(value.policy);
        setError("");
      }
    } catch (caught) { if (mounted.current) setError(caught.message); }
  };
  useEffect(() => { mounted.current = true; void load(); return () => { mounted.current = false; }; }, []);
  const completed = (value) => {
    snapshotRef.current = value; draftRef.current = value.policy;
    setSnapshot(value); setDraft(value.policy); setPending(null); setError(""); setWaiting(false); submitted.current = null;
    setNotice(`策略已确认 · 修订 ${value.revision}。仅影响后续派发，在途任务不变。`);
    void load(true);
  };
  useEffect(() => subscribeMetadataActions((event) => {
    if (!mounted.current || event?.type !== "completed" || event.kind !== "scheduling_confirm"
        || event.actor_id !== metadataActor()) return;
    const original = submitted.current;
    if (original?.request_id === event.request_id && original.epoch === currentIdentityEpoch()) completed(event.result);
    else if (!original) void load(true);
  }), []);
  const preview = () => mutation.run(async () => {
    setBusy(true); setError(""); setNotice("");
    try {
      const change = policyChange(snapshot, draft, reason);
      const value = await api("/v1/admin/scheduling/preview", { method: "POST", body: JSON.stringify(change) });
      if (mounted.current) setPending({ ...change, confirmation_hash: value.confirmation_hash });
    } catch (caught) { if (mounted.current) setError(caught.message); }
    finally { if (mounted.current) setBusy(false); }
  });
  const confirm = () => mutation.run(async () => {
    if (!pending) return;
    setBusy(true); setError("");
    try {
      const response = api("/v1/admin/scheduling/confirm", { method: "POST", body: JSON.stringify(pending) });
      const original = pendingMetadataAction(metadataActor());
      if (original?.kind === "scheduling_confirm") {
        submitted.current = { request_id: original.request_id, epoch: currentIdentityEpoch() }; setWaiting(true);
      }
      const value = await response;
      if (!mounted.current) return;
      if (submitted.current?.epoch === currentIdentityEpoch()) completed(value);
    } catch (caught) {
      if (mounted.current) {
        const unresolved = pendingMetadataAction(metadataActor());
        setWaiting(Boolean(unresolved && submitted.current && unresolved.request_id === submitted.current.request_id));
        if (!unresolved) submitted.current = null;
        setError(`确认结果未完成核对：${caught.message}。请核对原操作回执，不会重新提交策略。`);
      }
    } finally { if (mounted.current) setBusy(false); }
  });
  return <section className="detail-section scheduling-controls" aria-label="调度策略设置">
    <header><div><h2>任务分发策略</h2><span>全网配置 · 只影响新派发 · 不修改科学参数或现有运行任务</span></div>
      {snapshot && <small>修订 {snapshot.revision}</small>}</header>
    {!snapshot ? <DataLoadState label="正在读取调度策略" error={error} onRetry={load} /> : <>
      <div className="scheduling-strategies">{strategies.map(([key, title, detail]) =>
        <label key={key} className={draft.strategy === key ? "selected" : ""}>
          <input type="radio" name="dispatch-strategy" value={key} checked={draft.strategy === key}
            disabled={busy || Boolean(pending)} onChange={() => setDraft({ ...draft, strategy: key })} />
          <span><b>{title}</b><small>{detail}</small></span>
        </label>)}</div>
      <SmallBatchLimits draft={draft} onChange={setDraft} disabled={busy || Boolean(pending)} supportsParallel={supportsParallelBatch(snapshot)} />
      {parallelBatchEnabled(draft) && <p>按当前健康、可接活且兼容的机器最大槽位估计并行完工时间，包含当前忙碌槽位的容量，不按此刻空槽判断。不含排队等待，也不保证结束时刻；单个长单元不能拆开均摊。</p>}
      <p>资源、机主开关、项目授权、runtime 和 solver 硬门槛始终优先。未知耗时不会冒充小任务；保护等待不代表抢占正在运行的科学任务。</p>
      <label className="scheduling-reason">变更原因<input maxLength="1000" value={reason}
        disabled={busy || Boolean(pending)} onChange={event => setReason(event.target.value)} placeholder="说明本次策略调整的用途" /></label>
      {pending && <div className="scheduling-preview" role="status">
        即将选择「{strategies.find(([key]) => key === pending.policy.strategy)?.[1]}」，{smallBatchThresholdText(pending.policy)}，等待保护 {pending.policy.starvation_after_s} 秒。
        变更不重排已分配的 Attempt，也不改写 prepared 包；未激活预约按同一策略竞争。
      </div>}
      {error && <p role="alert" className="inline-error">{error}</p>}
      {notice && <p role="status">{notice}</p>}
      <footer>{pending ? <>
        <button className="button button-primary" disabled={busy || waiting} onClick={confirm}>{waiting ? "等待原操作回执" : "确认应用策略"}</button>
        <button className="button" disabled={busy || Boolean(error)} onClick={() => setPending(null)}>返回编辑</button>
        {error && !waiting && <button className="button" disabled={busy} onClick={async () => {
          setBusy(true);
          try {
            const current = await api("/v1/settings/scheduling");
            if (mounted.current) {
              setSnapshot(current); setDraft(current.policy); setPending(null); setError("");
              setNotice("已读取中心当前策略；请核对修订后再决定是否另作变更。");
            }
          } catch (caught) { if (mounted.current) setError(caught.message); }
          finally { if (mounted.current) setBusy(false); }
        }}>核对当前结果</button>}
      </> : <button className="button button-primary" disabled={busy || !reason.trim()} onClick={preview}>预览调度策略</button>}</footer>
    </>}
  </section>;
}
