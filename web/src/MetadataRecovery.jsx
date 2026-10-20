import { useEffect, useRef, useState } from "react";
import { api, currentIdentityEpoch } from "./api";
import { finishMetadataAction, metadataActor, metadataActionSending, pendingMetadataAction, subscribeMetadataActions, validateMetadataReceipt } from "./metadataActions";
import { watchPageReturn } from "./freshness";

export default function MetadataRecovery({ actorId, onRecovered }) {
  const [pending, setPending] = useState(() => pendingMetadataAction(actorId));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState(null);
  const [revision, setRevision] = useState(0);
  const inFlight = useRef(null);
  const trailing = useRef(false);
  const actorRef = useRef(actorId); actorRef.current = actorId;
  const attempted = useRef(null);
  const identityEpoch = useRef(currentIdentityEpoch());
  useEffect(() => {
    setError(""); setNotice(null); setBusy(false); attempted.current = null;
    const update = () => {
      if (identityEpoch.current !== currentIdentityEpoch()) {
        identityEpoch.current = currentIdentityEpoch(); attempted.current = null;
        inFlight.current?.controller.abort(); inFlight.current = null; trailing.current = false; setBusy(false);
      }
      setPending(pendingMetadataAction(actorId)); setRevision((value) => value + 1);
    };
    update(); const unsubscribe = subscribeMetadataActions(update);
    return () => { unsubscribe(); inFlight.current?.controller.abort(); inFlight.current = null; trailing.current = false; };
  }, [actorId]);
  useEffect(() => watchPageReturn(() => {
    if (inFlight.current) { trailing.current = true; return; }
    attempted.current = null; setRevision((value) => value + 1);
  }), []);
  const recover = async () => {
    if (!pending || pending.unreadable || pending.actor_id !== actorId || metadataActor() !== actorId || inFlight.current || metadataActionSending(pending.request_id)) return;
    const original = pending;
    const flight = { controller: new AbortController(), epoch: currentIdentityEpoch() };
    inFlight.current = flight; setBusy(true); setError("");
    try {
      const receipt = await api(`/v1/metadata-operations/${encodeURIComponent(original.request_id)}`, { signal: flight.controller.signal });
      validateMetadataReceipt(receipt, original);
      if (actorRef.current !== original.actor_id || currentIdentityEpoch() !== flight.epoch || inFlight.current !== flight) return;
      finishMetadataAction(original, undefined, receipt.result); setNotice({ actor_id: original.actor_id, epoch: flight.epoch, text: `${original.label}已完成，已核对原操作。` });
      try { await onRecovered?.(); } catch (caught) { if (actorRef.current === original.actor_id && currentIdentityEpoch() === flight.epoch && inFlight.current === flight) setError(`操作已完成，页面刷新失败：${caught.message}`); }
    } catch (caught) {
      if (actorRef.current === original.actor_id && currentIdentityEpoch() === flight.epoch && inFlight.current === flight) setError(caught.status === 404
        ? "暂未查到原操作回执；结果尚未确认，保留记录并继续核对。"
        : caught.message);
    } finally {
      if (inFlight.current === flight) {
        inFlight.current = null;
        if (actorRef.current === original.actor_id) {
          setBusy(false);
          if (trailing.current) { trailing.current = false; attempted.current = null; setRevision((value) => value + 1); }
        }
      }
    }
  };
  useEffect(() => {
    if (!pending || pending.unreadable || pending.actor_id !== actorId || metadataActor() !== actorId || document.visibilityState === "hidden" || metadataActionSending(pending.request_id) || attempted.current === pending.request_id) return;
    attempted.current = pending.request_id; void recover();
  }, [pending?.request_id, pending?.unreadable, revision, actorId]);
  const activeNotice = notice?.actor_id === actorId && notice?.epoch === currentIdentityEpoch() ? notice.text : "";
  if ((!pending || pending.actor_id !== actorId) && !activeNotice) return null;
  const running = pending && metadataActionSending(pending.request_id);
  return <section className="sync-warning" role="status" aria-label="管理操作回执"><div>
    {pending ? <><b>{pending.unreadable ? "上次管理操作记录无法读取" : `${pending.label}${running ? "正在提交" : "的结果待核对"}`}</b>
      <p>{pending.unreadable ? "请管理员核对操作结果，恢复本机会话记录后再继续。" : running ? "正在等待服务器确认。" : "将查询原操作的结果；核对后可继续保存设置。"}</p></> : <span>{activeNotice}</span>}
    {error && <p className="form-error" role="alert">{error}</p>}
    {pending && !pending.unreadable && <button className="button small" disabled={busy || running} onClick={recover}>{busy ? "正在核对" : "核对原操作"}</button>}
    {!pending && <button className="text-button" onClick={() => setNotice(null)}>关闭</button>}
  </div></section>;
}
