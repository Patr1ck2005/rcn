import { createReadScheduler } from "./readScheduler";
import { beginMetadataAction, finishMetadataAction, metadataActionSpec, releaseMetadataSender, setMetadataActor, validateMetadataReceipt } from "./metadataActions";

const tokenKey = "rcn-token";
const legacyTokenKey = "rcn-pilot-token";
const readScheduler = createReadScheduler({ limit: 1 });
let memberClientMode = false;
let readIdentityEpoch = 0;
export function currentIdentityEpoch() { return readIdentityEpoch; }

function identityChanged() {
  readIdentityEpoch += 1;
  setMetadataActor(null);
  readScheduler.cancelQueued(new DOMException("身份已变更，请重新读取", "AbortError"));
}

export function configureMemberClient(enabled) {
  const next = enabled === true;
  if (memberClientMode === next) return;
  memberClientMode = next;
  identityChanged();
}

export function isMemberClient() {
  return memberClientMode;
}

export async function detectMemberClient({ timeoutMs = 8000, signal } = {}) {
  const controller = new AbortController();
  const abort = () => controller.abort(signal?.reason);
  if (signal?.aborted) abort();
  else signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => controller.abort(new Error("读取客户端状态超时，请恢复本地服务后重试")), timeoutMs);
  try {
  const response = await fetch("/local/v1/capabilities", { cache: "no-store", signal: controller.signal });
  if (response.status === 404) { configureMemberClient(false); return null; }
  if (!response.ok) throw new Error("无法读取客户端状态，请恢复本地服务后重试");
  const capabilities = await response.json().catch(() => null);
  if (!capabilities || typeof capabilities.mode !== "string") throw new Error("客户端状态响应格式错误，请恢复本地服务后重试");
  configureMemberClient(capabilities?.mode === "member-client");
  return memberClientMode ? capabilities : null;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}

export function token() {
  if (memberClientMode) return "";
  const current = sessionStorage.getItem(tokenKey);
  if (current) return current;
  const legacy = sessionStorage.getItem(legacyTokenKey) || "";
  if (legacy) {
    sessionStorage.setItem(tokenKey, legacy);
    sessionStorage.removeItem(legacyTokenKey);
  }
  return legacy;
}

export function setToken(value) {
  if (memberClientMode) return;
  const normalized = value.trim();
  const previous = token();
  if (normalized) sessionStorage.setItem(tokenKey, normalized);
  else sessionStorage.removeItem(tokenKey);
  sessionStorage.removeItem(legacyTokenKey);
  if (previous !== normalized) identityChanged();
}

export async function api(path, options = {}) {
  // Do not turn a long audited write into an ambiguous timed-out action.
  const read = ["GET", "HEAD"].includes((options.method || "GET").toUpperCase());
  const { timeoutMs = read ? 30000 : 0, signal: callerSignal, ...requestOptions } = options;
  const controller = new AbortController();
  const abort = () => controller.abort(callerSignal?.reason);
  if (callerSignal?.aborted) abort();
  else callerSignal?.addEventListener("abort", abort, { once: true });
  const timer = timeoutMs > 0 ? setTimeout(() => controller.abort(new Error("请求超时，请重试")), timeoutMs) : null;
  let metadataOperation = null;
  let metadataSent = false;
  try {
  const identityEpoch = readIdentityEpoch;
  const headers = new Headers(options.headers || {});
  if (memberClientMode) headers.delete("Authorization");
  const currentToken = token();
  if (currentToken) headers.set("Authorization", `Bearer ${currentToken}`);
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const spec = !read && !memberClientMode && !headers.has("X-RCN-Request-ID")
    ? metadataActionSpec(path, options.method, options.body) : null;
  if (spec) {
    if (controller.signal.aborted) throw controller.signal.reason;
    metadataOperation = beginMetadataAction(spec, path, options.method);
    headers.set("X-RCN-Request-ID", metadataOperation.request_id);
  }
  const request = async () => {
  if (controller.signal.aborted) throw controller.signal.reason;
  if ((read || metadataOperation) && (identityEpoch !== readIdentityEpoch || currentToken !== token())) {
    throw new DOMException("身份已变更，请重新读取", "AbortError");
  }
  metadataSent = true;
  const response = await fetch(path, { cache: "no-store", ...requestOptions, headers, signal: controller.signal });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const detail = payload.detail;
    const restriction = payload.restriction || (
      detail && typeof detail === "object" && detail.reason_code ? detail : null
    );
    const baseMessage = typeof detail === "string"
      ? detail
      : detail?.message || restriction?.message || `请求失败 (${response.status})`;
    const nextAction = restriction?.next_action;
    const message = nextAction && !baseMessage.includes(nextAction)
      ? `${baseMessage} 下一步：${nextAction}`
      : baseMessage;
    const error = new Error(message);
    error.status = response.status;
    error.reasonCode = detail?.reason_code || restriction?.reason_code || null;
    error.restriction = restriction;
    error.payload = payload;
    if (metadataOperation && [400, 401, 403, 404, 409, 422].includes(response.status)) finishMetadataAction(metadataOperation);
    throw error;
  }
  const payload = response.status === 204 ? null : await response.json();
  if (read && (identityEpoch !== readIdentityEpoch || currentToken !== token())) {
    throw new DOMException("身份已变更，请重新读取", "AbortError");
  }
  if (metadataOperation) {
    if (response.status === 202) throw new Error("请求已接受，正在等待原操作完成，请核对原操作。");
    validateMetadataReceipt({ ...metadataOperation, state: "completed", result: payload }, metadataOperation);
    const obsolete = identityEpoch !== readIdentityEpoch || currentToken !== token();
    finishMetadataAction(metadataOperation, undefined, obsolete ? undefined : payload);
    if (obsolete) throw new DOMException("身份已变更，请核对原操作", "AbortError");
  }
  if (read && !memberClientMode && new URL(path, "http://rcn.invalid").pathname === "/v1/me") setMetadataActor(payload?.actor_id);
  return payload;
  };
  if (!read) return await request();
  const pathname = new URL(path, "http://rcn.invalid").pathname;
  const priority = pathname === "/v1/me" ? 0 : (
    pathname === "/v1/jobs" || pathname.startsWith("/v1/jobs/") || pathname === "/v1/operations/insights" ? 1 : 2
  );
  return await readScheduler.run(request, { signal: controller.signal, priority });
  } finally {
    try {
      if (metadataOperation && !metadataSent) finishMetadataAction(metadataOperation);
    } finally {
      try { if (metadataOperation) releaseMetadataSender(metadataOperation); }
      finally { clearTimeout(timer); callerSignal?.removeEventListener("abort", abort); }
    }
  }
}

export function parseSseFrames(buffered) {
  const frames = buffered.split(/\r?\n\r?\n/);
  const remainder = frames.pop() || "";
  const events = [];
  for (const frame of frames) {
    let eventType = "message";
    let id = null;
    const data = [];
    for (const line of frame.split(/\r?\n/)) {
      if (line.startsWith("event:")) eventType = line.slice(6).trim();
      else if (line.startsWith("id:")) id = Number(line.slice(3).trim()) || null;
      else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
    }
    if (!data.length) continue;
    try { events.push({ type: eventType, id, payload: JSON.parse(data.join("\n")) }); }
    catch { /* malformed frames are ignored; the next snapshot remains authoritative */ }
  }
  return { events, remainder };
}

export async function connectStateStream(onState, onStatus, signal, { lastSequence = 0 } = {}) {
  const headers = new Headers();
  const currentToken = token();
  if (currentToken) headers.set("Authorization", `Bearer ${currentToken}`);
  if (lastSequence) headers.set("Last-Event-ID", String(lastSequence));
  const response = await fetch("/v1/events/stream", { headers, signal });
  if (!response.ok || !response.body) throw new Error("实时连接不可用");
  onStatus("connected");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffered = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffered += decoder.decode(value, { stream: true });
    const parsed = parseSseFrames(buffered);
    buffered = parsed.remainder;
    for (const event of parsed.events) {
      if (event.type === "connected") {
        const transition = await onState({ _connected: true, ...event.payload });
        const resumeSequence = Number(transition?.resume_sequence);
        if (Number.isFinite(resumeSequence) && resumeSequence !== lastSequence) {
          await reader.cancel();
          return resumeSequence;
        }
      } else if (event.type === "state") {
        await onState(event.payload);
        lastSequence = Math.max(lastSequence, Number(event.payload?.sequence || event.id || 0));
      } else if (event.type === "maintenance" && event.payload?.reason_code === "release_draining") {
        await reader.cancel();
        const error = new Error("中心正在更新，稍后自动恢复连接");
        error.retryAfterMs = 5000;
        throw error;
      }
    }
  }
  onStatus("reconnecting");
  return lastSequence;
}
