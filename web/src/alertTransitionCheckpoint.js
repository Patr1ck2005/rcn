import { tokenRequestId } from "./tokenIssuance";
export const alertTransitionKey = (actorId) => `rcn-alert-transitions:${encodeURIComponent(actorId)}`;
export function alertTransitionCheckpoint(actorId, alert, status, hours = 0, now = Date.now()) {
  if (!actorId || !alert?.alert_id || !alert.status || !alert.last_seen_at || !Number.isInteger(alert.occurrence_count)) throw new Error("告警身份或当前版本尚未读取，请先刷新。");
  return { actor_id: actorId, alert_id: alert.alert_id, body: { request_id: tokenRequestId(), status,
    snoozed_until: hours ? new Date(now + hours * 3600000).toISOString() : null,
    expected_status: alert.status, expected_last_seen_at: alert.last_seen_at, expected_occurrence_count: alert.occurrence_count,
    expected_acknowledged_at: alert.acknowledged_at ?? null, expected_snoozed_until: alert.snoozed_until ?? null, expected_resolved_at: alert.resolved_at ?? null } };
}
export function loadAlertTransitions(storage, actorId) {
  const raw = storage.getItem(alertTransitionKey(actorId)); if (!raw) return {};
  const values = JSON.parse(raw);
  if (!values || typeof values !== "object" || Array.isArray(values) || Object.entries(values).some(([id, value]) => value?.actor_id !== actorId || value.alert_id !== id || !value.body?.request_id
    || !["expected_status", "expected_last_seen_at", "expected_occurrence_count", "expected_acknowledged_at", "expected_snoozed_until", "expected_resolved_at"].every((field) => Object.hasOwn(value.body, field)))) throw new Error("原告警操作检查点与当前身份或范围不匹配。");
  return values;
}
export function saveAlertTransition(storage, value) {
  const values = { ...loadAlertTransitions(storage, value.actor_id), [value.alert_id]: value };
  storage.setItem(alertTransitionKey(value.actor_id), JSON.stringify(values)); return values;
}
export function clearAlertTransition(storage, value) {
  const values = loadAlertTransitions(storage, value.actor_id); delete values[value.alert_id];
  if (Object.keys(values).length) storage.setItem(alertTransitionKey(value.actor_id), JSON.stringify(values)); else storage.removeItem(alertTransitionKey(value.actor_id));
  return values;
}
export async function recoverAlertTransition(request, value) {
  const receipt = await request(`/v1/admin/metadata-operations/${encodeURIComponent(value.body.request_id)}`);
  if (receipt?.request_id !== value.body.request_id || receipt.kind !== "alert_transition" || receipt.subject_id !== value.alert_id || receipt.result_id !== value.alert_id || receipt.state !== "completed") throw new Error("告警操作回执与原请求不匹配。");
  return receipt;
}
