import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import { useMutationGuard } from "./useMutationGuard";
import { clearOperationCheckpoint, metadataCheckpoint, readOperationCheckpoint, reassignmentCheckpoint, reassignmentPath, reassignmentReady, recoverMetadataJob, validateReassignment, writeOperationCheckpoint } from "./jobOperations";

export function useJobTransactions({ actorId, job, onUpdated, refresh }) {
  const mutation = useMutationGuard();
  const [saved] = useState(() => {
    try { return { metadata: readOperationCheckpoint(sessionStorage, actorId, job.job_id, "admin-job"), reassign: readOperationCheckpoint(sessionStorage, actorId, job.job_id, "reassign") }; }
    catch (caught) { return { error: caught.message }; }
  });
  const [operation, setOperation] = useState(saved.metadata ? { action: saved.metadata.ticket.action, work_unit_id: saved.metadata.ticket.work_unit_id } : null);
  const [reason, setReason] = useState(saved.metadata?.ticket.reason || "");
  const [ticket, setTicket] = useState(saved.metadata?.ticket || null);
  const [pendingTicket, setPendingTicket] = useState(saved.metadata || null);
  const [reassignment, setReassignment] = useState(saved.reassign || null);
  const [error, setError] = useState(saved.error || "");
  const [notice, setNotice] = useState("");
  const alive = useRef(true), currentJob = useRef(job.job_id), checkpointError = Boolean(saved.error);
  currentJob.current = job.job_id;
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const active = (jobId) => alive.current && currentJob.current === jobId;
  const persistTicket = (value) => { writeOperationCheckpoint(sessionStorage, value); if (active(value.subject_id)) setPendingTicket(value); };
  const persistReassignment = (value) => { writeOperationCheckpoint(sessionStorage, value); if (active(value.subject_id)) setReassignment(value); };
  const execute = (action) => mutation.run(async () => {
    if (checkpointError) return;
    const jobId = job.job_id;
    if (active(jobId)) { setError(""); setNotice(""); }
    try { await action(); }
    catch (caught) { if (active(jobId)) setError(`${caught.message} 原操作已保留；请核对原结果，勿新建替代操作。`); }
  });
  const finishMetadata = async (value, updatedJob) => {
    if (updatedJob?.job_id !== value.subject_id) throw new Error("确认响应与原 Job 不匹配。");
    if (!active(value.subject_id)) return;
    clearOperationCheckpoint(sessionStorage, value); setPendingTicket(null); setTicket(null); setOperation(null);
    setNotice("原 Job 操作已完成。"); if (onUpdated) await onUpdated(updatedJob); else await refresh?.();
  };
  const recoverTicket = () => execute(async () => {
    if (!pendingTicket) return;
    await finishMetadata(pendingTicket, await recoverMetadataJob(api, pendingTicket));
  });
  // Restoring a submitted ticket only queries its receipt; it never re-confirms.
  useEffect(() => { if (saved.metadata?.submitted) void recoverTicket(); }, []);
  const begin = (action, workUnitId = null) => {
    if (mutation.busy || pendingTicket?.submitted || reassignment || checkpointError) return;
    if (pendingTicket) clearOperationCheckpoint(sessionStorage, pendingTicket);
    setPendingTicket(null); setTicket(null); setOperation({ action, work_unit_id: workUnitId }); setReason(""); setError(""); setNotice("");
  };
  const preview = () => execute(async () => {
    if (!operation || pendingTicket?.submitted || reassignment) return;
    const jobId = job.job_id;
    const value = await api("/v1/admin/operations/preview", { method: "POST", body: JSON.stringify({ ...operation, job_id: jobId, reason }) });
    if (!active(jobId)) return;
    const checkpoint = metadataCheckpoint(actorId, jobId, value);
    persistTicket(checkpoint); setTicket(value);
  });
  const confirm = () => execute(async () => {
    if (!ticket || reassignment) return;
    const value = { ...metadataCheckpoint(actorId, job.job_id, ticket), submitted: true };
    persistTicket(value); // Write before sending, including an explicit retry.
    try {
      const result = await api("/v1/admin/operations/confirm", { method: "POST", body: JSON.stringify(value.body) });
      if (!result?.accepted) throw new Error("未收到原票据的确认回执。");
      await finishMetadata(value, result.job);
    } catch (caught) {
      try { await finishMetadata(value, await recoverMetadataJob(api, value)); }
      catch { throw caught; }
    }
  });
  const editTicket = () => {
    if (mutation.busy || pendingTicket?.submitted) return;
    if (pendingTicket) clearOperationCheckpoint(sessionStorage, pendingTicket);
    setPendingTicket(null); setTicket(null);
  };
  const finishReassignment = async (value, result) => {
    if (result.stage !== "reassigned") return false;
    if (!active(value.subject_id)) return true;
    clearOperationCheckpoint(sessionStorage, value); setReassignment(null); setNotice("原单元改派已完成。");
    if (onUpdated) await onUpdated(result.job); else await refresh?.(); return true;
  };
  const readReassignment = async (value) => validateReassignment(await api(reassignmentPath(value, true)), value);
  const applyReassignment = async (value, result) => {
    validateReassignment(result, value);
    if (!active(value.subject_id)) return true;
    if (await finishReassignment(value, result)) return true;
    persistReassignment({ ...value, stage: result.stage }); return false;
  };
  const recoverReassignment = () => execute(async () => {
    if (!reassignment) return;
    const result = await readReassignment(reassignment);
    if (result.stage !== "reassigned") reassignmentReady(result.job, reassignment);
    if (!await applyReassignment(reassignment, result)) setNotice("原改派仍在等待取消传播；可核对后继续同一操作。");
  });
  useEffect(() => { if (saved.reassign) void recoverReassignment(); }, []);
  const submitReassignment = (unit, target, auditReason) => execute(async () => {
    if (pendingTicket) throw new Error("请先处理已有 Job 操作票据。");
    const value = reassignment || reassignmentCheckpoint(actorId, job.job_id, unit, target, auditReason);
    persistReassignment(value);
    let result;
    if (reassignment) {
      try { result = await readReassignment(value); }
      catch (caught) { if (caught.status !== 404) throw caught; reassignmentReady(job, value); }
      if (result && await applyReassignment(value, result)) return;
      if (result && !reassignmentReady(result.job, value)) throw new Error("原尝试取消仍在传播，请稍后核对原改派。");
    }
    const post = async () => {
      try { return validateReassignment(await api(reassignmentPath(value), { method: "POST", body: JSON.stringify(value.body) }), value); }
      catch (caught) { try { return await readReassignment(value); } catch { throw caught; } }
    };
    result = await post();
    if (await applyReassignment(value, result)) return;
    reassignmentReady(result.job, value);
    const deadline = Date.now() + 120000;
    while (active(value.subject_id) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 2000));
      if (!active(value.subject_id)) return;
      result = await readReassignment(value);
      if (await applyReassignment(value, result)) return;
      if (reassignmentReady(result.job, value)) {
        result = await post();
        if (!await applyReassignment(value, result)) throw new Error("取消尚未传播完成，原改派没有完成，请核对后继续。");
        return;
      }
    }
    if (active(value.subject_id)) throw new Error("等待取消传播已达 120 秒，原改派仍未完成。");
  });
  return { busy: mutation.busy, operation, setOperation, reason, setReason, ticket, pendingTicket, reassignment, error, notice,
    locked: mutation.busy || checkpointError || Boolean(pendingTicket?.submitted || reassignment), begin, preview, confirm, editTicket, recoverTicket, recoverReassignment, submitReassignment };
}
