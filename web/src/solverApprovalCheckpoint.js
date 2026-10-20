import { tokenRequestId } from "./tokenIssuance";
export const solverApprovalKey = (actorId) => `rcn-solver-approval:${encodeURIComponent(actorId)}`;
export function solverApprovalCheckpoint(actorId, payload, draft) {
  if (!actorId || payload.approved_by !== actorId || !payload.project_id || !payload.execution_profile_id) throw new Error("审批身份或目标尚未确定。");
  return { actor_id: actorId, request_id: tokenRequestId(), payload: JSON.parse(JSON.stringify(payload)), draft: JSON.parse(JSON.stringify(draft)) };
}
export function loadSolverApproval(storage, actorId) {
  const raw = storage.getItem(solverApprovalKey(actorId)); if (!raw) return null;
  const value = JSON.parse(raw);
  if (value?.actor_id !== actorId || !value.request_id || value.payload?.approved_by !== actorId || !value.payload.project_id || !value.payload.execution_profile_id) throw new Error("原审批检查点与当前身份或范围不匹配。");
  return value;
}
export function saveSolverApproval(storage, value) { storage.setItem(solverApprovalKey(value.actor_id), JSON.stringify(value)); return value; }
export function clearSolverApproval(storage, value) { storage.removeItem(solverApprovalKey(value.actor_id)); }
export function validateSolverApproval(approval, value) {
  if (!approval?.approval_id || approval.project_id !== value.payload.project_id || approval.execution_profile_id !== value.payload.execution_profile_id) throw new Error("审批回执与原请求范围不匹配。");
  return approval; // A revoked approval remains revoked; replay never reissues it.
}
export async function recoverSolverApproval(request, value) {
  const receipt = await request(`/v1/admin/metadata-operations/${encodeURIComponent(value.request_id)}`);
  if (receipt?.request_id !== value.request_id || receipt.kind !== "solver_approval" || receipt.state !== "completed" || !receipt.result_id) throw new Error("审批回执与原请求标识不匹配。");
  const approvals = await request("/v1/solver-approvals");
  const approval = validateSolverApproval(approvals.find((item) => item.approval_id === receipt.result_id), value);
  return { approval, approvals };
}
