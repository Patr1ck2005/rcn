import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import { useMutationGuard } from "./useMutationGuard";
import { clearOperationCheckpoint, readOperationCheckpoint, writeOperationCheckpoint } from "./jobOperations";

export function usePressureOverride(actorId, machineId, refresh) {
  const mutation = useMutationGuard();
  const [saved] = useState(() => {
    try { return { checkpoint: readOperationCheckpoint(sessionStorage, actorId, machineId, "pressure") }; }
    catch (caught) { return { error: caught.message }; }
  });
  const [checkpoint, setCheckpoint] = useState(saved.checkpoint || null);
  const [error, setError] = useState(saved.error || "");
  const [notice, setNotice] = useState("");
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const perform = (work) => mutation.run(async () => {
    if (saved.error) return;
    setError(""); setNotice("");
    try { await work(); }
    catch (caught) { if (alive.current) setError(`${caught.message} 原票据已保留，核对或显式重试使用同一票据。`); }
  });
  const finish = async (value, result) => {
    if (result?.machine_id !== machineId) throw new Error("压力覆盖结果与原机器不匹配。");
    if (!alive.current) return;
    clearOperationCheckpoint(sessionStorage, value); setCheckpoint(null); setNotice("原压力覆盖已确认；有效期以原操作为准。"); await refresh?.();
  };
  const recover = () => perform(async () => {
    if (!checkpoint) return;
    const receipt = await api(`/v1/admin/metadata-operations/${encodeURIComponent(checkpoint.body.ticket_id)}`);
    if (receipt?.kind !== "pressure_override" || receipt.request_id !== checkpoint.body.ticket_id || receipt.subject_id !== machineId || receipt.result_id !== machineId || receipt.state !== "completed") throw new Error("压力覆盖回执与原票据不匹配。");
    await finish(checkpoint, receipt.result);
  });
  useEffect(() => { if (saved.checkpoint?.submitted) void recover(); }, []);
  const preview = (body) => perform(async () => {
    if (checkpoint?.submitted) return;
    const ticket = await api(`/v1/admin/machines/${encodeURIComponent(machineId)}/pressure-override/preview`, { method: "POST", body: JSON.stringify(body) });
    if (!alive.current) return;
    if (ticket?.machine_id !== machineId || !ticket.ticket_id || !ticket.confirmation_hash) throw new Error("预览票据与原机器不匹配。");
    const value = { kind: "pressure", actor_id: actorId, subject_id: machineId, ticket, body: { ticket_id: ticket.ticket_id, confirmation_hash: ticket.confirmation_hash }, submitted: false };
    writeOperationCheckpoint(sessionStorage, value); setCheckpoint(value);
  });
  const confirm = () => perform(async () => {
    if (!checkpoint || checkpoint.subject_id !== machineId || checkpoint.actor_id !== actorId) throw new Error("原票据与当前机器或身份不匹配。");
    const value = { ...checkpoint, submitted: true };
    writeOperationCheckpoint(sessionStorage, value); setCheckpoint(value);
    try { await finish(value, await api(`/v1/admin/machines/${encodeURIComponent(machineId)}/pressure-override/confirm`, { method: "POST", body: JSON.stringify(value.body) })); }
    catch (caught) {
      try {
        const receipt = await api(`/v1/admin/metadata-operations/${encodeURIComponent(value.body.ticket_id)}`);
        if (receipt?.kind !== "pressure_override" || receipt.request_id !== value.body.ticket_id || receipt.subject_id !== machineId || receipt.result_id !== machineId || receipt.state !== "completed") throw caught;
        await finish(value, receipt.result);
      } catch { throw caught; }
    }
  });
  const edit = () => {
    if (mutation.busy || checkpoint?.submitted) return;
    if (checkpoint) clearOperationCheckpoint(sessionStorage, checkpoint);
    setCheckpoint(null);
  };
  return { busy: mutation.busy, preview: checkpoint?.ticket || null, locked: Boolean(saved.error || checkpoint?.submitted), error, notice, createPreview: preview, confirm, recover, edit };
}
