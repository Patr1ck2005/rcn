export const tokenIssuanceKey = (actorId) => `rcn-pending-token-issuance:${encodeURIComponent(actorId)}`;
export function tokenRequestId() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  // getRandomValues is also available for the isolated HTTP development UI.
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
export function pendingTokenIssuance(storage, actorId) {
  const raw = storage.getItem(tokenIssuanceKey(actorId));
  if (!raw) return {};
  const value = JSON.parse(raw);
  if (!value || Array.isArray(value) || typeof value !== "object") throw new Error("Token 签发检查点无法读取，请先核对已有 Token");
  return value;
}
export function markTokenIssuance(storage, actorId, userId, pending, agent = false) {
  const value = pendingTokenIssuance(storage, actorId);
  if (pending) value[userId] = { user_id: userId, started_at: new Date().toISOString(), request_id: tokenRequestId(), ...(agent ? { agent: true } : {}) };
  else delete value[userId];
  if (Object.keys(value).length) storage.setItem(tokenIssuanceKey(actorId), JSON.stringify(value));
  else storage.removeItem(tokenIssuanceKey(actorId));
  return value;
}
