// Only non-secret operation IDs are kept so a lost reply can be read back.
const importKey = "rcn-connection-import";
export const connectionStages = {
  preview: "等待确认", staged: "等待确认", pending_confirmation: "等待确认", awaiting_confirmation: "等待确认",
  importing: "正在导入", validating: "正在校验连接包", configuring: "正在保存本机连接",
  connecting: "正在连接中心", probing: "正在核验身份", confirmed: "正在接入中心", committing: "正在保存连接与身份",
  completed: "连接已完成", connected: "连接已完成", succeeded: "连接已完成",
  failed: "导入未完成", unknown: "结果待确认", recovery_required: "需要恢复本机状态",
};
export const importComplete = (value) => ["completed", "connected", "succeeded"].includes(value?.state);
export const importPreview = (value) => ["preview", "staged", "pending_confirmation", "awaiting_confirmation"].includes(value?.state);
export const importRunning = (value) => ["importing", "validating", "configuring", "connecting", "probing", "confirmed", "committing"].includes(value?.state);

export function rememberConnectionImport(id) {
  for (const name of ["localStorage", "sessionStorage"]) {
    try { if (id) globalThis[name].setItem(importKey, id); else globalThis[name].removeItem(importKey); } catch { /* Recovery remains available in the current view. */ }
  }
}
export function pendingConnectionImport() {
  for (const name of ["localStorage", "sessionStorage"]) {
    try { const id = globalThis[name].getItem(importKey); if (/^[a-zA-Z0-9_-]{1,120}$/.test(id || "")) return id; } catch { /* Try the other browser store. */ }
  }
  return null;
}

const reasonActions = {
  connection_bundle_invalid: "连接包格式或校验不通过，请向管理员索取为你签发的原始连接包。",
  invalid_connection_bundle: "连接包格式或校验不通过，请向管理员索取为你签发的原始连接包。",
  connection_bundle_expired: "连接包已过期，请管理员重新签发。",
  connection_owner_mismatch: "连接包的成员身份与当前身份不同，请核对包的归属。",
  owner_mismatch: "连接包的成员身份与当前身份不同，请核对包的归属。",
  center_login_required: "个人登录已失效，请重新导入连接包或使用高级登录。",
  token_revoked: "当前凭据已撤销，请管理员重新签发连接包。",
  center_unreachable: "暂时无法连接中心，请检查网络后运行连接自检。",
  ssh_host_key_mismatch: "中心主机指纹与连接包不一致，请联系管理员核对后重新签发连接包。",
  host_key_mismatch: "中心主机指纹与连接包不一致，请联系管理员核对后重新签发连接包。",
  connection_import_in_progress: "原导入仍在执行，请恢复同一导入查看结果。",
  connection_import_not_found: "本机没有这条导入记录，请重新选择原始连接包。",
  local_config_invalid: "本机连接配置无法读取，请运行连接自检，并按检查结果恢复。",
  local_secret_unavailable: "本机加密登录无法读取，请使用当前 Windows 用户重新导入连接包。",
  agent_registration_forbidden: "当前身份没有配置 Agent 的权限，请管理员核对成员授权。",
};

export function connectionError(error) {
  const code = error?.reasonCode || error?.reason_code || error?.payload?.detail?.reason_code || error?.restriction?.reason_code;
  if (reasonActions[code]) return `${reasonActions[code]}（${code}）`;
  if (code?.startsWith("member_connection_import_")) {
    const kind = code.slice("member_connection_import_".length);
    const action = kind === "center_login_required" ? "个人登录已失效或撤销，请管理员提供当前有效的本人接入包。"
      : kind === "center_permission_denied" ? "中心已响应，但当前身份权限不足，请管理员核对本人的授权。"
      : /center_unavailable|ssh_channel_unavailable/.test(kind) ? "中心或网络暂不可达，请恢复连接后继续原接入编号。"
      : kind === "upstream_port_in_use" ? "转发端口被其他程序占用，请运行自检并核对原连接。"
      : /different_member|personal_identity_mismatch|owner_or_root_changed/.test(kind) ? "连接包与本机个人身份不一致，请管理员核对本人接入包。"
      : /different_center|center_trust_changed|existing_trust_unselected/.test(kind) ? "中心连接或信任记录发生变化，请管理员核对中心与主机指纹。"
        : /not_found/.test(kind) ? "本机没有这条导入记录，请重新选择原始连接包。"
          : /ssh_prerequisite/.test(kind) ? "本机 SSH 客户端尚未就绪，请运行连接自检并按建议恢复。"
            : /operations_busy/.test(kind) ? "本机仍有操作执行中，请待原操作结束后按原编号恢复导入。"
              : /changed|commit_failed/.test(kind) ? "本机状态已变化，原身份和任务记录已保留。请运行自检并按原编号恢复，不要删除本机配置。"
                : "连接包未通过完整校验，请使用管理员为本人提供的原始 ZIP 包，或将诊断报告交给 Agent。";
    return `${action}（${code}）`;
  }
  if (code?.startsWith("member_")) return `${safeDiagnosticText(error?.message || "本机连接未就绪，请运行连接自检并按检查结果恢复。", 500)}（${safeDiagnosticText(code, 120)}）`;
  if (error?.status === 401) return reasonActions.center_login_required;
  if (error?.status === 403) return "当前身份没有执行此操作的权限，请管理员核对授权。";
  if (!error?.status && (error instanceof TypeError || error?.name === "AbortError")) return "本机服务或网络暂时不可达。请恢复服务后重试；已确认的导入请按原编号恢复。";
  return safeDiagnosticText(error?.message || "操作未完成，请运行连接自检查看下一步。", 600);
}

export async function uploadConnectionBundle(file) {
  if (file.size > 1024 * 1024) throw new Error("个人连接包超过 1 MiB，请选择管理员提供的原始接入 ZIP。");
  const response = await fetch("/local/v1/connection-imports", { method: "POST", body: file, cache: "no-store",
    headers: { "Content-Type": "application/zip", "X-RCN-Filename": encodeURIComponent(file.name) } });
  const value = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = value.detail || value;
    const error = new Error(typeof detail === "string" ? detail : detail.message || `连接包导入失败 (${response.status})`);
    error.status = response.status; error.reasonCode = detail.reason_code; error.payload = value;
    throw error;
  }
  if (!/^[a-zA-Z0-9_-]{1,120}$/.test(value.import_id || "") || typeof value.state !== "string") throw new Error("导入响应缺少有效记录编号，请运行连接自检。");
  return value;
}

export function safeDiagnosticText(value, limit = 1200) {
  return String(value ?? "")
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/gi, "[已隐藏私钥]")
    .replace(/\bBearer\s+[^\s,;]+/gi, "Bearer [已隐藏]")
    .replace(/\b((?:access[_-]?)?token|password|secret|private[_-]?key|authorization)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi, "$1=[已隐藏]")
    .replace(/https?:\/\/[^\s<>"']+/gi, (raw) => { try { const url = new URL(raw); url.username = ""; url.password = ""; url.search = ""; url.hash = ""; return url.toString(); } catch { return "[连接地址]"; } })
    .slice(0, limit);
}

export function sanitizedDoctorReport(result) {
  return {
    schema_version: 1, diagnostic_id: safeDiagnosticText(result?.diagnostic_id, 120), ok: result?.ok === true,
    observed_at: safeDiagnosticText(result?.observed_at, 100), secrets_included: false,
    summary: safeDiagnosticText(result?.summary),
    checks: (Array.isArray(result?.checks) ? result.checks : []).map((item) => ({
      stage: safeDiagnosticText(item.stage, 100),
      status: ["passed", "warning", "failed", "skipped"].includes(item.status) ? item.status : "skipped",
      reason_code: safeDiagnosticText(item.reason_code, 120), message: safeDiagnosticText(item.message),
      next_action: safeDiagnosticText(item.next_action), help_slug: /^[a-z0-9-]+$/.test(item.help_slug || "") ? item.help_slug : null,
    })),
    next_actions: (Array.isArray(result?.next_actions) ? result.next_actions : []).map((item) => safeDiagnosticText(typeof item === "string" ? item : item?.message || item?.next_action || "")),
  };
}

export function downloadDoctorReport(result) {
  const report = sanitizedDoctorReport(result);
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
  const link = document.createElement("a"); link.href = url; link.download = "RCN-connection-diagnostics.json";
  document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
