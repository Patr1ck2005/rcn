import { tokenRequestId } from "./tokenIssuance";

export const operationCheckpointKey = (actorId, subjectId, kind) => `rcn-operation:${kind}:${encodeURIComponent(actorId)}:${encodeURIComponent(subjectId)}`;
export function readOperationCheckpoint(storage, actorId, subjectId, kind) {
  const raw = storage.getItem(operationCheckpointKey(actorId, subjectId, kind));
  if (!raw) return null;
  const value = JSON.parse(raw);
  if (value?.actor_id !== actorId || value.subject_id !== subjectId || value.kind !== kind || !value.body) throw new Error("原操作检查点与当前身份或对象不匹配，请先核对原操作。");
  if (kind === "admin-job") {
    const expected = metadataCheckpoint(actorId, subjectId, value.ticket);
    if (JSON.stringify(value.body) !== JSON.stringify(expected.body)) throw new Error("原票据检查点不完整，请先核对原操作。");
  }
  if (kind === "reassign" && (!value.work_unit_id || !value.body.operation_id || !value.body.target_machine_id
    || !Object.hasOwn(value.body, "expected_attempt_id") || !Object.hasOwn(value.body, "expected_external_run_id"))) throw new Error("原改派检查点不完整，请先核对原操作。");
  if (kind === "pressure" && (value.ticket?.machine_id !== subjectId || value.ticket?.ticket_id !== value.body.ticket_id
    || !value.body.ticket_id || value.ticket?.confirmation_hash !== value.body.confirmation_hash || !value.body.confirmation_hash)) throw new Error("原压力覆盖检查点不完整，请先核对原操作。");
  return value;
}
export function writeOperationCheckpoint(storage, value) {
  if (!value.actor_id || !value.subject_id) throw new Error("操作身份尚未加载，不能提交。");
  storage.setItem(operationCheckpointKey(value.actor_id, value.subject_id, value.kind), JSON.stringify(value));
  return value;
}
export function clearOperationCheckpoint(storage, value) {
  storage.removeItem(operationCheckpointKey(value.actor_id, value.subject_id, value.kind));
}
export function metadataCheckpoint(actorId, jobId, ticket) {
  if (ticket?.job_id !== jobId || !ticket.ticket_id || !ticket.confirmation_hash || (ticket.issued_by && ticket.issued_by !== actorId)) throw new Error("预览票据与当前 Job 或操作者不匹配，未提交确认。");
  return { kind: "admin-job", actor_id: actorId, subject_id: jobId, ticket,
    body: { ticket_id: ticket.ticket_id, confirmation_hash: ticket.confirmation_hash }, submitted: false };
}
export async function recoverMetadataJob(request, checkpoint) {
  const receipt = await request(`/v1/admin/metadata-operations/${encodeURIComponent(checkpoint.body.ticket_id)}`);
  if (receipt?.request_id !== checkpoint.body.ticket_id || receipt.kind !== "admin_job" || receipt.subject_id !== checkpoint.subject_id || receipt.result_id !== checkpoint.subject_id || receipt.state !== "completed") throw new Error("原操作回执与票据或 Job 不匹配。");
  const job = await request(`/v1/jobs/${encodeURIComponent(checkpoint.subject_id)}?view=operational`);
  if (job?.job_id !== checkpoint.subject_id) throw new Error("原操作已完成，但返回的 Job 身份不匹配。");
  return job;
}
export function reassignmentCheckpoint(actorId, jobId, unit, target, reason) {
  if (!jobId || !unit?.work_unit_id || !target || !reason.trim()) throw new Error("请提供原单元、目标机器和改派原因。");
  const attempt = unit.attempts?.at(-1);
  return { kind: "reassign", actor_id: actorId, subject_id: jobId, work_unit_id: unit.work_unit_id, stage: "unconfirmed",
    body: { target_machine_id: target, reason: reason.trim(), expected_attempt_id: attempt?.attempt_id || null,
      expected_external_run_id: attempt?.external_run_id || null, operation_id: tokenRequestId() } };
}
export function reassignmentPath(checkpoint, query = false) {
  const base = `/v1/jobs/${encodeURIComponent(checkpoint.subject_id)}/units/${encodeURIComponent(checkpoint.work_unit_id)}`;
  return query ? `${base}/reassign-operations/${encodeURIComponent(checkpoint.body.operation_id)}` : `${base}/reassign`;
}
export function validateReassignment(result, checkpoint) {
  const body = checkpoint.body;
  if (result?.job?.job_id !== checkpoint.subject_id || result.operation_id !== body.operation_id
    || result.target_machine_id !== body.target_machine_id || result.expected_attempt_id !== body.expected_attempt_id
    || result.expected_external_run_id !== body.expected_external_run_id || !["cancel_requested", "reassigned"].includes(result.stage)) throw new Error("改派回执与原操作、Job 或尝试身份不匹配。");
  return result;
}
export function reassignmentReady(job, checkpoint) {
  if (job?.job_id !== checkpoint.subject_id) throw new Error("改派状态返回了其他 Job。");
  const unit = job.work_units?.find((item) => item.work_unit_id === checkpoint.work_unit_id);
  const attempt = unit?.attempts?.at(-1);
  if (!unit || (attempt?.attempt_id || null) !== checkpoint.body.expected_attempt_id || (attempt?.external_run_id || null) !== checkpoint.body.expected_external_run_id) throw new Error("原尝试已变更；停止续接改派，请核对原操作，不能取消或重试新的 Attempt。");
  return ["queued", "cancelled", "failed_retriable"].includes(unit.status)
    && (!attempt || ["cancelled", "failed", "abandoned"].includes(attempt.state));
}
