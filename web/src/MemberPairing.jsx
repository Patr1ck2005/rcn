import { useEffect, useRef, useState } from "react";
import { CheckCircle2, Copy, RefreshCw, UserRoundPlus } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "./api";
import { useMutationGuard } from "./useMutationGuard";
import { usePageRefresh } from "./usePageRefresh";
import { memberAgentTargets, memberIdentityVerified, validateMemberAgentBundle } from "./memberAgentConfig";
import { safeDiagnosticText, sanitizedDoctorReport } from "./memberConnectionModel";

const pairingKey = "rcn-member-pairing";
const pauseKey = "rcn-member-pairing-resume-paused";
const pauseEvent = "rcn-member-pairing-pause";
let pausedInMemory = false;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function pairingResumePaused() {
  for (const store of ["localStorage", "sessionStorage"]) {
    try { if (globalThis[store].getItem(pauseKey) === "true") return true; } catch { /* Use the other store or this page's state. */ }
  }
  return pausedInMemory;
}
export function pausePairingResume() {
  pausedInMemory = true;
  for (const store of ["localStorage", "sessionStorage"]) {
    try { globalThis[store].setItem(pauseKey, "true"); } catch { /* The current view is also notified. */ }
  }
  globalThis.window?.dispatchEvent(new Event(pauseEvent));
}
function allowPairingResume() {
  pausedInMemory = false;
  for (const store of ["localStorage", "sessionStorage"]) { try { globalThis[store].removeItem(pauseKey); } catch { /* The view can continue this explicit action. */ } }
}
export function savedPairingId() {
  for (const store of ["localStorage", "sessionStorage"]) {
    try { const value = globalThis[store].getItem(pairingKey); if (uuidPattern.test(value || "")) return value; } catch { /* The local API also retains the original record. */ }
  }
  return null;
}
export function rememberPairingId(id) {
  for (const store of ["localStorage", "sessionStorage"]) {
    try { if (id) globalThis[store].setItem(pairingKey, id); else globalThis[store].removeItem(pairingKey); } catch { /* Keep the in-memory record and local API recovery. */ }
  }
}
export function pairingError(failure) {
  const code = failure?.reasonCode || failure?.reason_code;
  const copy = {
    member_pairing_rate_limited: "申请或查询过于频繁，请等一分钟后恢复原申请。",
    member_pairing_authentication_required: "本机配对登录无法核验，请保留原申请并联系管理员。",
    member_pairing_content_conflict: "原申请内容与本机记录不同，请恢复原申请；不要重复申请。",
    member_pairing_not_found: "原申请暂时无法读取，请恢复网络后重试原编号。",
    member_pairing_existing_session: "本机已有个人登录，请先核对当前身份；如需切换，请先退出个人登录。",
    member_pairing_expired: "申请已过期，请联系管理员并重新申请。",
    member_pairing_rejected: "管理员已拒绝此申请，请联系管理员核对姓名和设备。",
    member_pairing_revoked: "此连接已由管理员撤销，请联系管理员。",
    member_pairing_existing_login_unreadable: "本机已有登录无法读取，请先运行连接自检，保留原身份与配置。",
    member_pairing_existing_center_conflict: "本机已绑定其他中心，请先核对原连接；接入不会自动覆盖已有中心。",
    member_pairing_existing_identity_conflict: "本机已登录其他成员，请核对本人身份并先退出原登录。",
    member_pairing_local_binding_changed: "原配对记录与本机安全登录不一致，请保留记录并联系管理员。",
    member_pairing_center_binding_changed: "中心返回的配对信息与原申请不同，请联系管理员核对原申请。",
    member_pairing_local_content_conflict: "本机已有不同内容的原申请，请恢复原申请，或在它结束后重新申请。",
    member_pairing_transfer_in_progress: "本机仍在上传或下载，请等待原任务传输结束后恢复原申请。",
    member_pairing_identity_unconfirmed: "中心身份尚未核验通过，请恢复原申请或联系管理员。",
    center_dns_unavailable: "中心域名暂时无法解析，请核对管理员提供的链接与本机网络，再恢复原申请。",
    center_certificate_invalid: "中心 HTTPS 证书未通过验证，请核对系统时间与中心链接；请管理员处理证书后恢复原申请。",
    center_tls_failed: "与中心的 HTTPS 握手未完成，请检查本机网络后恢复原申请；持续失败时请管理员核对 TLS 配置。",
    center_tunnel_unavailable: "公网入口已响应，但中心 Tunnel 暂不可用。请管理员恢复入口通道后，再恢复原申请。",
    center_origin_unavailable: "公网入口已响应，但中心回源服务暂不可达。请管理员检查中心服务，再恢复原申请。",
    center_gateway_tls_failed: "公网入口与中心之间的 TLS 握手失败，请管理员检查回源证书与 TLS 配置，再恢复原申请。",
  };
  if (copy[code]) return copy[code];
  if (code && /https|center_url|center_invalid|url_invalid/.test(code)) return "中心链接无效，请使用管理员提供的 HTTPS 链接。";
  if (failure?.status === 429) return copy.member_pairing_rate_limited;
  return "暂时无法完成接入。请检查中心链接与网络，然后恢复原申请；已保存的身份和配置会保留。";
}
export function pairingState(record) {
  if (record?.state === "approved") {
    if (record.phase === "connected" && record.agent_configuration && record.doctor_state === "completed" && record.doctor?.ok === true) return "completed";
    if (record.phase === "connected" && (record.doctor_state !== "completed" || record.doctor?.ok !== true)) return "failed";
    if (record.phase === "agent_configured") return "checking";
    if (record.phase === "personal_login_saved") return "configuring";
  }
  return record?.state || "unknown";
}
const stateLabels = { pending: "等待管理员批准", approved: "已批准，正在接入", connecting: "正在连接中心", configuring: "正在配置 Agent", checking: "正在检查连接", completed: "已连接，可以提交任务", connected: "已连接，可以提交任务", offline: "中心连接待恢复", rejected: "申请未获批准", expired: "申请已过期", revoked: "连接已撤销", failed: "接入需要恢复", unknown: "原申请结果待确认" };
const terminalStates = ["rejected", "expired", "revoked"];
export const pairingFinished = (record) => ["completed", "connected"].includes(pairingState(record));

export function PairingApplicationForm({ draft, onChange, busy, onSubmit }) {
  const change = (key, value) => onChange({ ...draft, [key]: value });
  return <form className="member-pairing-fields" onSubmit={onSubmit}>
    <label>课题组中心链接<input aria-label="课题组中心链接" type="url" value={draft.center_url} required pattern="https://.*" placeholder="粘贴管理员提供的 HTTPS 链接" autoComplete="url" disabled={busy} onChange={(event) => change("center_url", event.target.value)} /></label>
    <div className="member-pairing-form-row"><label>你的姓名<input aria-label="你的姓名" value={draft.name} maxLength={80} required autoComplete="name" disabled={busy} onChange={(event) => change("name", event.target.value)} /></label><label>设备名称<input aria-label="设备名称" value={draft.device_name} maxLength={80} required placeholder="例如：小林的笔记本" disabled={busy} onChange={(event) => change("device_name", event.target.value)} /></label></div>
    <div className="member-pairing-form-row"><label>使用的 Agent<select aria-label="入组使用的 Agent" value={draft.target} disabled={busy} onChange={(event) => { const target = event.target.value; onChange({ ...draft, target, label: !draft.label.trim() || draft.label === `我的 ${memberAgentTargets[draft.target].label}` ? `我的 ${memberAgentTargets[target].label}` : draft.label }); }}>{Object.entries(memberAgentTargets).map(([key, value]) => <option key={key} value={key}>{value.label}</option>)}</select></label><label>Agent 名称<input aria-label="入组 Agent 名称" value={draft.label} maxLength={80} required disabled={busy} onChange={(event) => change("label", event.target.value)} /></label></div>
    <p>批准后客户端会自动保存个人登录、生成独立 Agent 配置并检查连接。仅提交任务无需贡献电脑或安装 COMSOL。</p>
    <button className="button button-primary" disabled={busy || !draft.name.trim() || !draft.device_name.trim() || !draft.label.trim()}><UserRoundPlus size={17} />{busy ? "正在发送申请…" : "申请加入课题组"}</button>
  </form>;
}

export function PairingStatus({ record, busy, instructions, notice, onRefresh, onCopy, onRestart, onResend, onDoctor }) {
  const state = pairingState(record);
  const doctor = record.doctor ? sanitizedDoctorReport(record.doctor) : null;
  return <div className="member-pairing-status" aria-live="polite"><h3>{stateLabels[state] || "接入需要恢复"}</h3>
    {record.group_name && <p>课题组：{safeDiagnosticText(record.group_name, 120)}</p>}
    <dl className="member-metadata"><div><dt>姓名</dt><dd>{safeDiagnosticText(record.name, 80) || "已保存到本机申请"}</dd></div><div><dt>设备</dt><dd>{safeDiagnosticText(record.device_name, 80) || "已保存到本机申请"}</dd></div><div><dt>原申请编号</dt><dd><code>{record.pairing_id}</code></dd></div></dl>
    {state === "pending" && <><p>把下面的配对码告诉管理员，并通过本人联系渠道核对姓名和设备。</p><div className="member-pairing-code-box"><span>配对码</span><strong>{record.short_code || "正在读取原配对码"}</strong></div><p>页面打开时每 5 秒查看一次审批状态。关闭页面后可继续同一申请。</p>{record.expires_at && <p>有效至 {new Date(record.expires_at).toLocaleString("zh-CN", { hour12: false })}</p>}</>}
    {["approved", "connecting", "configuring", "checking"].includes(state) && <p role="status">正在使用原申请完成个人登录、Agent 配置与自检，请稍候。</p>}
    {state === "rejected" && <p>请联系管理员核对本人信息，确认后可发起新的申请。</p>}
    {state === "expired" && <p>本次申请已结束，重新申请后请提供新的配对码。</p>}
    {state === "revoked" && <p>请联系管理员恢复授权，再重新接入。</p>}
    {state === "unknown" && <p>发送结果尚未确认。原申请编号已保留，请读取原结果，避免重复身份。</p>}
    {state === "failed" && <p>批准记录已保留。处理检查项后，点击“重新检查原配对”，继续同一申请。</p>}
    {state === "offline" && <p>原身份与 Agent 配置已保留，请恢复网络后读取原申请，再继续提交任务。</p>}
    {state === "failed" && doctor && <div><p>{doctor.summary}</p><ul>{doctor.checks.filter((item) => item.status === "failed" || item.status === "warning").map((item, index) => <li key={index}>{item.message}{item.next_action && ` ${item.next_action}`}</li>)}</ul></div>}
    {record.error && <p className="form-error" role="alert">{pairingError(record.error)}</p>}
    {pairingFinished(record) && <div className="member-result"><CheckCircle2 size={21} /><div><b>个人身份与连接自检已通过</b><p>将接入说明交给本机 Agent，即可按现有项目规则准备并提交任务。</p>{instructions && <><button className="button button-primary" onClick={onCopy}><Copy size={16} />复制指令给 Agent</button><details className="member-bindings"><summary>查看接入指令</summary><pre className="member-instructions">{instructions}</pre></details></>}<div className="member-actions"><Link className="button" to="/app/submit">提交任务</Link><Link to="/app/help/member-task-package">如何准备任务包</Link></div></div></div>}
    {!pairingFinished(record) && <div className="member-actions"><button className="button" disabled={busy} onClick={onRefresh}><RefreshCw size={16} />{busy ? "正在恢复原申请…" : "恢复原申请"}</button>{state === "failed" && onDoctor && <button className="button" disabled={busy} onClick={onDoctor}>重新检查原配对</button>}{state === "unknown" && onResend && <button className="button" disabled={busy} onClick={onResend}>按原编号重试发送</button>}{terminalStates.includes(state) && <button className="button" disabled={busy} onClick={onRestart}>重新申请</button>}</div>}
    {notice && <p className="member-notice" role="status">{notice}</p>}
  </div>;
}

export default function MemberPairing({ session, onSession, onReadyChange }) {
  const [draft, setDraft] = useState({ center_url: session?.center_url?.startsWith("https://") ? session.center_url : "", name: "", device_name: "", target: "codex", label: "我的 Codex" });
  const [pairingId, setPairingId] = useState(savedPairingId);
  const [record, setRecord] = useState(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [instructions, setInstructions] = useState("");
  const [paused, setPaused] = useState(pairingResumePaused);
  const [loading, setLoading] = useState(() => !pairingResumePaused());
  const [groupName, setGroupName] = useState("");
  const [startingNew, setStartingNew] = useState(false);
  const [connectionUnconfirmed, setConnectionUnconfirmed] = useState(false);
  const currentId = useRef(pairingId);
  const originalRequest = useRef(null);
  const observationRevision = useRef(0);
  const mounted = useRef(true);
  const mutation = useMutationGuard();
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    const suspend = () => { observationRevision.current += 1; setPaused(true); setLoading(false); setInstructions(""); };
    window.addEventListener(pauseEvent, suspend);
    return () => window.removeEventListener(pauseEvent, suspend);
  }, []);
  const apply = async (value, isCurrent = () => mounted.current) => {
    if (pairingResumePaused()) return;
    if (value?.state === "not_started") { if (isCurrent()) { setRecord(null); originalRequest.current = null; } return; }
    if (!value || !uuidPattern.test(value.pairing_id || "") || typeof value.state !== "string") throw new Error("配对响应格式不完整");
    if (record && currentId.current && value.pairing_id !== currentId.current) throw new Error("原配对编号不一致");
    if (!isCurrent() || pairingResumePaused()) return;
    if (value.resume_paused === true || value.phase === "resume_paused") {
      currentId.current = value.pairing_id; rememberPairingId(value.pairing_id); setPairingId(value.pairing_id); setRecord(value);
      pausePairingResume();
      return;
    }
    let verifiedSession = null;
    let setupInstructions = "";
    if (value.state === "approved" && value.agent_configuration) {
      verifiedSession = await api("/local/v1/session");
      if (!isCurrent() || pairingResumePaused()) return;
      const agent = value.agent_configuration;
      setupInstructions = validateMemberAgentBundle(agent, verifiedSession, agent.target, agent.agent_id).setup_instructions;
    }
    if (!isCurrent() || pairingResumePaused()) return;
    currentId.current = value.pairing_id; rememberPairingId(value.pairing_id); setPairingId(value.pairing_id); setRecord(value);
    setInstructions(setupInstructions);
    if (verifiedSession) onSession(verifiedSession);
    setError(""); setConnectionUnconfirmed(false);
  };
  const read = usePageRefresh(async ({ signal, isCurrent }) => {
    const revision = observationRevision.current;
    const current = () => isCurrent() && revision === observationRevision.current;
    try {
      const value = await api(record && currentId.current ? `/local/v1/member-pairing/${encodeURIComponent(currentId.current)}` : "/local/v1/member-pairing", { signal });
      if (current()) await apply(value, current);
    } catch (failure) { if (current() && failure.status !== 404) { setError(pairingError(failure)); setConnectionUnconfirmed(true); } }
    finally { if (current()) setLoading(false); }
  }, { initial: true, intervalMs: pairingId ? 5000 : 0, listen: false, enabled: !paused && !startingNew && !terminalStates.includes(pairingState(record)) && !mutation.busy });
  const recover = (action = "resume") => mutation.run(async () => {
    observationRevision.current += 1;
    const wasPaused = paused;
    allowPairingResume(); setPaused(false); setLoading(true); setError("");
    try {
      let id = currentId.current;
      if (!id) {
        const original = await api("/local/v1/member-pairing");
        if (!mounted.current || pairingResumePaused()) return;
        if (original?.state === "not_started") { await apply(original); return; }
        if (!uuidPattern.test(original?.pairing_id || "")) throw new Error("原配对编号无法读取");
        id = original.pairing_id; currentId.current = id; rememberPairingId(id); setPairingId(id);
      }
      const value = await api(`/local/v1/member-pairing/${encodeURIComponent(id)}/${action}`, { method: "POST", body: "{}" });
      if (mounted.current) await apply(value);
    } catch (failure) {
      if (mounted.current) { setError(pairingError(failure)); setConnectionUnconfirmed(true); if (wasPaused) pausePairingResume(); }
    } finally { if (mounted.current) setLoading(false); }
  });
  const submit = (event) => mutation.run(async () => {
    const id = currentId.current || crypto.randomUUID();
    currentId.current = id; rememberPairingId(id); setPairingId(id); setError(""); setStartingNew(false);
    setRecord({ pairing_id: id, state: "unknown", name: draft.name.trim(), device_name: draft.device_name.trim() });
    const payload = originalRequest.current || { pairing_id: id, center_url: draft.center_url.trim(), name: draft.name.trim(), device_name: draft.device_name.trim(), agent: draft.target, label: draft.label.trim() };
    originalRequest.current = payload;
    try {
      const value = await api("/local/v1/member-pairing", { method: "POST", body: JSON.stringify(payload) });
      if (mounted.current) await apply(value);
    }
    catch (failure) { if (mounted.current) setError(pairingError(failure)); }
  }, event);
  const restart = () => {
    if (!terminalStates.includes(pairingState(record))) return;
    currentId.current = null; originalRequest.current = null; rememberPairingId(null); setPairingId(null); setRecord(null); setInstructions(""); setError(""); setNotice(""); setStartingNew(true);
  };
  const copy = async () => {
    try { await navigator.clipboard.writeText(instructions); if (mounted.current) setNotice("已复制指令，可直接交给本机 Agent。"); }
    catch { if (mounted.current) setError("复制未完成，请展开接入指令手动复制。"); }
  };
  const checkGroup = () => mutation.run(async () => {
    try {
      const value = await api("/local/v1/member-pairing/group", { method: "POST", body: JSON.stringify({ center_url: draft.center_url.trim() }) });
      if (!value?.online_member_pairing || typeof value.group_name !== "string") throw new Error("课题组暂未开放在线配对");
      if (mounted.current) { setGroupName(safeDiagnosticText(value.group_name, 120)); setError(""); }
    } catch (failure) { if (mounted.current) { setGroupName(""); setError(pairingError(failure)); } }
  });
  const ready = pairingFinished(record) && !paused && !connectionUnconfirmed && memberIdentityVerified(session);
  useEffect(() => { onReadyChange?.(ready); }, [ready, onReadyChange]);
  if (!loading && !record && session?.connected) return null;
  const displayRecord = pairingFinished(record) && (connectionUnconfirmed || !memberIdentityVerified(session)) ? { ...record, state: "offline" } : record;
  return <section className="member-panel member-pairing" aria-label="加入课题组"><header><div><h2><UserRoundPlus size={20} /> {ready ? "课题组已连接" : "加入课题组"}</h2><p>{ready ? "把接入指令交给本机 Agent，即可开始准备任务。" : "填写本人信息，管理员批准后自动完成连接与 Agent 配置。"}</p></div><span className="member-badge">{displayRecord ? stateLabels[pairingState(displayRecord)] || "接入待恢复" : "在线配对"}</span></header>
    {paused ? <div><p>个人登录已退出。点击继续配对会读取本机原申请，并在批准后恢复登录。</p><button className="button" disabled={mutation.busy} onClick={() => recover("resume")}>继续配对</button></div> : loading && !record ? <p role="status">正在读取本机配对状态…</p> : record ? <PairingStatus record={displayRecord} busy={mutation.busy} instructions={instructions} notice={notice} onRefresh={() => recover("resume")} onDoctor={() => recover("doctor")} onCopy={copy} onRestart={restart} onResend={originalRequest.current ? () => submit() : null} /> : <>
      {pairingId && <p role="status">已保留原申请编号。继续填写会恢复同一申请，请与原申请信息保持一致：<code>{pairingId}</code></p>}
      <PairingApplicationForm draft={draft} onChange={(value) => { setDraft(value); if (value.center_url !== draft.center_url) setGroupName(""); }} busy={mutation.busy} onSubmit={submit} />
      <div className="member-actions"><button className="button small" disabled={mutation.busy || !draft.center_url.trim()} onClick={checkGroup}>核对课题组中心</button>{groupName && <span role="status">课题组：{groupName}</span>}</div>
    </>}
    {error && <p className="form-error" role="alert">{error}</p>}
  </section>;
}
