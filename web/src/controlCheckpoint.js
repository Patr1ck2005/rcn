export const controlScope = (kind, action, machineIds = []) => ({ kind, action, machine_ids: [...new Set(machineIds)].sort() });
export const controlCheckpointKey = (actorId, scope) => `rcn-control:${encodeURIComponent(actorId)}:${encodeURIComponent(JSON.stringify(scope))}`;
const sameIds = (left, right) => JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());

export function controlCheckpoint(actorId, scope, ticket, body) {
  if (!actorId || !ticket?.ticket_id || !ticket.confirmation_hash || ticket.ticket_id !== body.ticket_id || ticket.confirmation_hash !== body.confirmation_hash
    || ticket.action !== scope.action || (ticket.issued_by && ticket.issued_by !== actorId)) throw new Error("原控制票据与当前身份或操作不匹配。");
  if (scope.machine_ids.length && !sameIds(scope.machine_ids, (ticket.targets || []).map((target) => target.machine_id))) throw new Error("原控制票据的目标与当前范围不匹配。");
  // Explicit allowlist: break_glass_pin and other credentials never persist.
  const frozen = { ticket_id: body.ticket_id, confirmation_hash: body.confirmation_hash };
  for (const key of ["typed_machine_id", "process_set_hash"]) if (Object.hasOwn(body, key)) frozen[key] = body[key];
  const safeTicket = Object.fromEntries(["schema_version", "ticket_id", "action", "targets", "reason", "impact", "requires_break_glass", "confirmation_hash", "issued_by", "created_at", "expires_at"]
    .filter((key) => Object.hasOwn(ticket, key)).map((key) => [key, ticket[key]]));
  return { actor_id: actorId, scope, ticket: JSON.parse(JSON.stringify(safeTicket)), body: frozen };
}
export function loadControlCheckpoint(storage, actorId, scope) {
  const raw = storage.getItem(controlCheckpointKey(actorId, scope));
  if (!raw) return null;
  const value = JSON.parse(raw);
  if (value.actor_id !== actorId || JSON.stringify(value.scope) !== JSON.stringify(scope)) throw new Error("控制检查点属于其他身份或范围。");
  return controlCheckpoint(actorId, scope, value.ticket, value.body);
}
export function saveControlCheckpoint(storage, value) {
  const sanitized = controlCheckpoint(value.actor_id, value.scope, value.ticket, value.body);
  storage.setItem(controlCheckpointKey(value.actor_id, value.scope), JSON.stringify(sanitized));
  return sanitized;
}
export function clearControlCheckpoint(storage, value) { storage.removeItem(controlCheckpointKey(value.actor_id, value.scope)); }
export function controlResumeBody(value, current) {
  const body = { ...value.body };
  if (value.ticket.requires_break_glass) {
    if (!current.break_glass_pin || current.typed_machine_id !== value.body.typed_machine_id) throw new Error("续接原票据需要重新输入应急 PIN 和原机器 ID。");
    body.break_glass_pin = current.break_glass_pin;
  }
  return body;
}
export function validateControlScope(run, value) {
  if (run?.ticket_id !== value.body.ticket_id || !run.operation_id || (run.action && run.action !== value.scope.action)
    || (run.requested_by && run.requested_by !== value.actor_id)) throw new Error("控制回执与原身份或票据不匹配。");
  const targets = run.request_targets?.length ? run.request_targets : run.targets;
  if (value.scope.machine_ids.length && (!targets || !sameIds(value.scope.machine_ids, targets.map((target) => target.machine_id)))) throw new Error("控制回执与原目标范围不匹配。");
  return run;
}
