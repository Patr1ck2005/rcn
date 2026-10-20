import { tokenRequestId } from "./tokenIssuance";

const listeners = new Set();
const sending = new Set();
let actor = null;
export const metadataActionKey = (actorId) => `rcn-metadata-action-v1:${encodeURIComponent(actorId)}`;
const changed = (event) => { for (const listener of listeners) listener(event); };
export function subscribeMetadataActions(listener) { listeners.add(listener); return () => listeners.delete(listener); }
export function setMetadataActor(actorId) { actor = actorId || null; changed(); }
export function metadataActor() { return actor; }
export function metadataActionSending(requestId) { return sending.has(requestId); }

// Mutations with an existing credential/ticket/submission protocol keep it.
export function metadataActionSpec(path, method, body) {
  const pathname = new URL(path, "http://rcn.invalid").pathname;
  const verb = (method || "GET").toUpperCase();
  let payload = {};
  if (typeof body === "string") { try { payload = JSON.parse(body); } catch { return null; } }
  const routes = [
    ["PUT", /^\/v1\/users\/([^/]+)$/, "user_update", "保存用户"],
    ["DELETE", /^\/v1\/users\/([^/]+)\/tokens\/[^/]+$/, "user_token_revoke", "撤销访问凭据"],
    ["PUT", /^\/v1\/projects\/([^/]+)$/, "project_update", "保存项目授权"],
    ["POST", /^\/v1\/admin\/project-registrations\/([^/]+)\/review$/, "project_registration_review", "审核项目登记"],
    ["PUT", /^\/v1\/projects\/([^/]+)\/trusted-users\/[^/]+$/, "project_trusted_user_add", "添加项目成员"],
    ["DELETE", /^\/v1\/projects\/([^/]+)\/trusted-users\/[^/]+$/, "project_trusted_user_remove", "移除项目成员"],
    ["POST", /^\/v1\/admin\/projects\/([^/]+)\/freeze$/, "project_freeze", "更新项目冻结状态"],
    ["PUT", /^\/v1\/admin\/people\/([^/]+)\/submission-policy$/, "personal_submission_policy", "保存个人提交策略"],
    ["PUT", /^\/v1\/machines\/([^/]+)\/policy$/, "machine_policy", "保存机器共享策略"],
    ["PUT", /^\/v1\/machines\/([^/]+)\/execution-tuning$/, "machine_execution_tuning", "保存机器执行设置"],
    ["PUT", /^\/v1\/machines\/([^/]+)\/external-comsol-consent$/, "machine_external_comsol_consent", "保存机器授权"],
    ["POST", /^\/v1\/admin\/resource-policies\/([^/]+)\/confirm$/, "resource_policy_confirm", "确认资源策略"],
    ["DELETE", /^\/v1\/solver-approvals\/([^/]+)$/, "solver_approval_revoke", "撤销执行环境批准"],
    ["POST", /^\/v1\/admin\/member-admissions\/([^/]+)\/revoke$/, "member_admission_revoke", "撤销成员邀请或贡献授权"],
    ["POST", /^\/v1\/admin\/onboarding\/([^/]+)\/preflight$/, "onboarding_preflight", "检查机器接入条件"],
    ["POST", /^\/v1\/admin\/jobs\/([^/]+)\/units\/[^/]+\/abandon-and-retry$/, "abandon_attempt", "放弃旧尝试并重算"],
  ];
  for (const [routeMethod, pattern, kind, label] of routes) {
    const match = pathname.match(pattern);
    if (verb === routeMethod && match) return { kind, subject_id: decodeURIComponent(match[1]), label,
      ...(kind === "abandon_attempt" ? { attempt_id: payload?.expected_attempt_id, external_run_id: payload?.expected_external_run_id ?? null } : {}) };
  }
  if (verb === "POST" && pathname === "/v1/profiles") return { kind: "profile_create", subject_id: payload?.profile_id, label: "创建执行类型版本" };
  if (verb === "POST" && pathname === "/v1/project-registrations") return { kind: "project_registration", subject_id: payload?.project_id, label: "登记项目" };
  const global = {
    "PUT /v1/settings/features": ["feature_settings", "保存系统设置"],
    "PUT /v1/admin/break-glass/pin": ["break_glass_pin", "更新管理员 PIN"],
    "POST /v1/admin/scheduling/confirm": ["scheduling_confirm", "确认调度策略"],
  }[`${verb} ${pathname}`];
  return global ? { kind: global[0], subject_id: "global", label: global[1] } : null;
}

export function pendingMetadataAction(actorId, storage) {
  if (!actorId) return null;
  try {
    const raw = (storage || globalThis.sessionStorage).getItem(metadataActionKey(actorId));
    if (!raw) return null;
    const value = JSON.parse(raw);
    if (value.schema_version !== 1 || value.actor_id !== actorId ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value.request_id) ||
        typeof value.kind !== "string" || typeof value.subject_id !== "string" ||
        typeof value.path !== "string" || !value.path.startsWith("/v1/") || typeof value.method !== "string" ||
        value.kind === "abandon_attempt" && (typeof value.attempt_id !== "string" || !(value.external_run_id === null || typeof value.external_run_id === "string"))) throw new Error("invalid checkpoint");
    return value;
  } catch { return { actor_id: actorId, unreadable: true }; }
}

export function beginMetadataAction(spec, path, method, storage = sessionStorage) {
  const actorId = actor;
  if (!actorId) throw new Error("正在核验当前身份，请稍后再保存。");
  if (pendingMetadataAction(actorId, storage)) throw new Error("上次管理操作的结果尚未确认，请先核对原操作。");
  if (!spec.subject_id || typeof spec.subject_id !== "string") throw new Error("操作对象不完整，请刷新后重试。");
  const value = { schema_version: 1, actor_id: actorId, request_id: tokenRequestId(),
    kind: spec.kind, subject_id: spec.subject_id, label: spec.label, path,
    method: method.toUpperCase(), created_at: new Date().toISOString(),
    ...(spec.kind === "abandon_attempt" ? { attempt_id: spec.attempt_id, external_run_id: spec.external_run_id } : {}) };
  if (spec.kind === "abandon_attempt" && typeof value.attempt_id !== "string") throw new Error("原尝试身份不完整，请刷新后重试。");
  // Never persist bodies: they may contain a PIN, invitation or other secret.
  try { storage.setItem(metadataActionKey(actorId), JSON.stringify(value)); }
  catch { throw new Error("无法保存操作记录，请恢复浏览器会话存储后再提交。"); }
  sending.add(value.request_id); changed();
  return value;
}

export function finishMetadataAction(value, storage = sessionStorage, result) {
  const current = pendingMetadataAction(value.actor_id, storage);
  if (current?.request_id === value.request_id) storage.removeItem(metadataActionKey(value.actor_id));
  changed(result === undefined ? undefined : { ...value, type: "completed", result });
}
export function releaseMetadataSender(value) { sending.delete(value.request_id); changed(); }

export function validateMetadataReceipt(receipt, pending) {
  if (!receipt || receipt.request_id !== pending.request_id || receipt.kind !== pending.kind || receipt.subject_id !== pending.subject_id) {
    throw new Error("回执与原操作不匹配，保留原操作记录。");
  }
  if (receipt.state !== "completed") throw new Error(receipt.state === "reconciliation_required"
    ? "原操作的执行结果需要人工核对；不会自动再次执行。"
    : "原操作仍在处理中，请稍后再次核对。");
  if (!Object.hasOwn(receipt, "result") || !receipt.result || typeof receipt.result !== "object" || Array.isArray(receipt.result)) throw new Error("原操作回执不完整，保留记录并继续核对。");
  const result = receipt.result;
  const identityField = {
    user_update: "user_id", user_token_revoke: "user_id", profile_create: "profile_id",
    project_update: "project_id", project_registration: "project_id", project_registration_review: "registration_id",
    project_trusted_user_add: "project_id", project_trusted_user_remove: "project_id", project_freeze: "project_id",
    personal_submission_policy: "person_id", machine_policy: "machine_id", machine_execution_tuning: "machine_id",
    machine_external_comsol_consent: "machine_id", resource_policy_confirm: "profile_id", solver_approval_revoke: "approval_id",
  }[pending.kind];
  if (identityField && result[identityField] !== pending.subject_id) throw new Error("回执与原操作对象不匹配，保留原操作记录。");
  if (pending.kind === "break_glass_pin" && result.configured !== true) throw new Error("PIN 更新回执不完整，保留原操作记录。");
  if (pending.kind === "scheduling_confirm" && (!Number.isInteger(result.revision) || result.revision < 1
      || !result.policy || typeof result.policy !== "object" || Array.isArray(result.policy))) throw new Error("调度策略回执不完整，保留原操作记录。");
  if (pending.kind === "abandon_attempt") {
    const path = new URL(pending.path, "http://rcn.invalid").pathname;
    const match = path.match(/^\/v1\/admin\/jobs\/([^/]+)\/units\/([^/]+)\/abandon-and-retry$/);
    if (!match || result.job_id !== pending.subject_id || result.work_unit_id !== decodeURIComponent(match[2])
        || result.abandoned_attempt_id !== pending.attempt_id || (result.abandoned_external_run_id ?? null) !== pending.external_run_id
        || !["queued", "replayed"].includes(result.outcome)) throw new Error("回执与原尝试不匹配，保留原操作记录。");
  }
  if (pending.kind === "onboarding_preflight" && (result.machine_id !== pending.subject_id || result.run_id !== `ssh-preflight-${pending.request_id}`)) throw new Error("回执与原机器检查不匹配，保留原操作记录。");
  return receipt.result;
}
