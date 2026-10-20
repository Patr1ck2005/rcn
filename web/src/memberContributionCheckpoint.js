// Contribution recovery owns its local protocol; no invite or request payload
// may enter browser storage. A second checkpoint is reserved for safe pause.
const canonicalUuid = (value) => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
export const contributionKey = (scope) => `rcn-member-contribution:${encodeURIComponent(scope.actor_id)}:${encodeURIComponent(scope.center_url)}`;
export const contributionNotFound = (error) => error.status === 404 && error.reasonCode === "contribution_operation_not_found";

export function contributionScope(session, state) {
  const actor = session?.actor?.actor_id;
  const center = session?.center_url?.replace(/\/$/, "");
  if (!actor || !center || !canonicalUuid(state?.contribution_id)) throw new Error("请先核对原个人身份与本机接入状态。");
  return { actor_id: actor, center_url: center, contribution_id: state.contribution_id };
}

export function safeContributionCheckpoint(scope, value) {
  if (!canonicalUuid(value.operation_id) || !["setup", "preferences"].includes(value.kind)
      || !["setup", "preferences", "pause", "resume"].includes(value.action)
      || (value.kind === "setup") !== (value.action === "setup")
      || value.actor_id !== scope.actor_id || value.center_url !== scope.center_url || value.contribution_id !== scope.contribution_id
      || !Number.isSafeInteger(value.expected_revision) || value.expected_revision < 0 || typeof value.machine_id !== "string") {
    throw new Error("接入请求检查点与当前身份、中心或本机不匹配。");
  }
  return { ...scope, operation_id: value.operation_id, kind: value.kind, action: value.action,
    machine_id: value.machine_id, expected_revision: value.expected_revision };
}

export function loadContributionCheckpoints(storage, scope) {
  const raw = storage.getItem(contributionKey(scope));
  if (!raw) return [];
  const values = JSON.parse(raw);
  if (!Array.isArray(values) || values.length > 2) throw new Error("原接入请求检查点无效，请保留记录后核对本机状态。");
  return values.map((value) => safeContributionCheckpoint(scope, value));
}

export function saveContributionCheckpoints(storage, scope, values) {
  const safe = values.map((value) => safeContributionCheckpoint(scope, value));
  if (safe.length > 2) throw new Error("请先核对原接入请求。");
  if (safe.length) storage.setItem(contributionKey(scope), JSON.stringify(safe));
  else storage.removeItem(contributionKey(scope));
  return safe;
}

export function validateContributionReceipt(value, checkpoint) {
  const original = value?.operation;
  if (!original || original.operation_id !== checkpoint.operation_id || original.kind !== checkpoint.kind
      || original.actor_id !== checkpoint.actor_id || original.center_url !== checkpoint.center_url
      || original.expected_revision !== checkpoint.expected_revision
      || checkpoint.machine_id && original.machine_id !== checkpoint.machine_id
      || !/^[a-f0-9]{64}$/.test(original.payload_sha256 || "")
      || !["executing", "unknown", "completed", "failed"].includes(original.status)) {
    throw new Error("原接入回执与请求身份或机器不匹配，请保留原编号。");
  }
  if ((["completed", "failed"].includes(original.status) || value.result) && (!value.result || value.result.contribution_id !== checkpoint.contribution_id
      || !Number.isSafeInteger(value.result.revision) || value.result.revision < checkpoint.expected_revision
      || value.result.machine_id !== original.machine_id)) throw new Error("原接入结果缺少本机范围证明。");
  if (original.status === "failed" && (!original.error?.reason_code || typeof original.error.message !== "string")) throw new Error("原接入失败回执缺少原因。");
  return value;
}

export async function readContributionOriginal(request, checkpoint) {
  return validateContributionReceipt(await request(`/local/v1/contribution/operations/${checkpoint.operation_id}`), checkpoint);
}

export async function submitContribution(request, checkpoint, payload) {
  try {
    return validateContributionReceipt(await request(`/local/v1/contribution/${checkpoint.kind}`, {
      method: "POST", body: JSON.stringify({ ...payload, operation_id: checkpoint.operation_id, expected_revision: checkpoint.expected_revision }),
    }), checkpoint);
  } catch (error) {
    try { return await readContributionOriginal(request, checkpoint); }
    catch (recovery) {
      const failure = new Error(`${error.message || "响应中断"}。原请求编号已保留，请核对原结果。`);
      failure.status = error.status;
      failure.notDelivered = contributionNotFound(recovery);
      throw failure;
    }
  }
}
