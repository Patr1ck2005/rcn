import { useEffect, useRef, useState } from "react";
import { RefreshCw, UserRoundCheck } from "lucide-react";
import { api } from "./api";
import { usePageRefresh } from "./usePageRefresh";
import { useMutationGuard } from "./useMutationGuard";
import { safeDiagnosticText } from "./memberConnectionModel";
import "./memberClient.css";

const decisionKey = (actorId) => `rcn-member-pairing-decisions:${actorId}`;
export function loadPairingDecisions(actorId) {
  try {
    const value = JSON.parse(sessionStorage.getItem(decisionKey(actorId)) || "{}");
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};
    return Object.fromEntries(Object.entries(value).filter(([id, item]) => /^[0-9a-f-]{36}$/i.test(id)
      && item && ["approve", "reject"].includes(item.action) && item.body && typeof item.body === "object"
      && (item.action === "reject" || item.body.create_new === true || item.body.create_new === false && typeof item.body.member_id === "string")));
  } catch { return {}; }
}
function saveDecisions(actorId, value) {
  // Only application UUIDs and the explicit approval choice are stored.
  try { sessionStorage.setItem(decisionKey(actorId), JSON.stringify(value)); } catch { /* Server read-back remains authoritative. */ }
}
export function pairingApprovalChoice(mode, memberId) {
  if (mode === "new") return { create_new: true };
  if (mode === "existing" && memberId) return { create_new: false, member_id: memberId };
  return null;
}
export function pairingCodeMatches(actual, supplied) {
  return typeof actual === "string" && actual.length > 0 && actual.toUpperCase() === supplied.trim().toUpperCase();
}
const states = { pending: "待审批", approved: "已批准", rejected: "已拒绝", expired: "已过期", revoked: "已撤销" };
const decisionError = (failure) => {
  const code = failure.reasonCode;
  if (code === "member_pairing_existing_member_invalid") return "所选成员已停用或不具备成员角色，请核对成员列表后重新选择。";
  if (code === "member_pairing_terminal") return "这条申请已结束，请读取原申请的当前状态。";
  if (code === "member_pairing_approval_conflict") return "原申请已有不同的审批结果，请读取原申请并核对管理员审计。";
  if (failure.status === 401 || failure.status === 403) return "管理员登录已失效或权限不足，请重新登录后读取原申请。";
  return "审批结果尚未确认，请先核对原申请；再次提交只会重试原审批内容。";
};

function PairingReview({ pairing, users, ready, decision, busy, onDecide, onRead }) {
  const [mode, setMode] = useState("");
  const [memberId, setMemberId] = useState("");
  const [code, setCode] = useState("");
  const [identityChecked, setIdentityChecked] = useState(false);
  const choice = pairingApprovalChoice(mode, memberId);
  const eligible = users.filter((user) => user.active && user.roles?.includes("member"));
  return <article className="member-pairing-review" aria-label={`${pairing.name}的入组申请`}>
    <header><div><h3>{safeDiagnosticText(pairing.name, 80)}</h3><p>{safeDiagnosticText(pairing.device_name, 80)}</p></div><span className="member-badge">{states[pairing.state] || "状态待核对"}</span></header>
    <dl className="member-metadata"><div><dt>配对码</dt><dd><code className="member-pairing-code">{pairing.short_code}</code></dd></div><div><dt>申请编号</dt><dd><code>{pairing.pairing_id}</code></dd></div><div><dt>有效至</dt><dd>{pairing.expires_at ? new Date(pairing.expires_at).toLocaleString("zh-CN", { hour12: false }) : "由中心核验"}</dd></div></dl>
    {decision ? <div className="member-pairing-unknown" role="status"><b>原审批结果待核对</b><p>{decision.action === "reject" ? "原操作：拒绝申请。" : decision.body.create_new ? "原操作：新建成员并批准。" : `原操作：批准关联成员 ${decision.body.member_id}。`} 已保留原申请编号与选择。</p><div className="member-actions"><button className="button" disabled={busy} onClick={onRead}>核对原审批结果</button><button className="button" disabled={busy} onClick={() => onDecide(pairing, decision)}>重试原审批</button></div></div>
      : <fieldset className="member-pairing-fields" disabled={busy || !ready}>
        <label>核对成员提供的配对码<input aria-label={`核对 ${pairing.name} 的配对码`} value={code} maxLength={12} autoComplete="off" onChange={(event) => setCode(event.target.value)} /></label>
        <label className="member-consent"><input type="checkbox" checked={identityChecked} onChange={(event) => setIdentityChecked(event.target.checked)} /><span>我已通过本人联系渠道核对姓名、设备及配对码。</span></label>
        <label>身份处理<select aria-label={`选择 ${pairing.name} 的身份处理`} value={mode} onChange={(event) => { setMode(event.target.value); setMemberId(""); }}><option value="">请选择已有成员或新建成员</option><option value="existing">关联已有成员</option><option value="new">新建独立成员</option></select></label>
        {mode === "existing" && <label>已有成员<select aria-label={`为 ${pairing.name} 选择已有成员`} value={memberId} onChange={(event) => setMemberId(event.target.value)}><option value="">请选择成员身份</option>{eligible.map((user) => <option key={user.user_id} value={user.user_id}>{user.display_name || user.user_id} · {user.user_id}</option>)}</select></label>}
        {mode === "new" && <p>将为此申请新建独立成员；姓名相同也不会自动合并。</p>}
        <p>无个人策略时按中心默认策略开通提交权限；已有成员的个人策略继续沿用。机器贡献仍需另行选择。</p>
        <div className="member-actions"><button className="button button-primary" disabled={!choice || !identityChecked || !pairingCodeMatches(pairing.short_code, code)} onClick={() => onDecide(pairing, { action: "approve", body: choice })}>批准并接入</button><button className="button" onClick={() => onDecide(pairing, { action: "reject", body: {} })}>拒绝申请</button></div>
      </fieldset>}
  </article>;
}

export default function AdminMemberPairing({ actorId, users = [], ready = true, onRefresh }) {
  const [pairings, setPairings] = useState([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [decisions, setDecisions] = useState(() => loadPairingDecisions(actorId));
  const decisionsRef = useRef(decisions);
  const mutation = useMutationGuard();
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const commitDecisions = (value) => { decisionsRef.current = value; if (mounted.current) setDecisions(value); saveDecisions(actorId, value); };
  const apply = (value) => {
    if (!Array.isArray(value?.pairings)) throw new Error("申请列表格式不完整");
    setPairings(value.pairings); setLoaded(true);
    const remaining = { ...decisionsRef.current };
    for (const item of value.pairings) if (item.state !== "pending") delete remaining[item.pairing_id];
    if (Object.keys(remaining).length !== Object.keys(decisionsRef.current).length) commitDecisions(remaining);
  };
  const refresh = usePageRefresh(async ({ signal, isCurrent }) => {
    try { const value = await api("/v1/admin/member-pairings", { signal }); if (isCurrent()) { apply(value); setError(""); } }
    catch (failure) { if (isCurrent()) setError(failure.status === 401 || failure.status === 403 ? "需要管理员身份才能读取入组申请，请重新登录。" : "入组申请暂时无法读取，请恢复连接后刷新。"); }
  }, { initial: true, intervalMs: 5000, listen: false, enabled: !mutation.busy });
  // The refresh hook disposes polls and pending reads when leaving this tab.
  // Mutations may have reached the server; their checkpoint is retained.
  const decide = (pairing, proposed) => mutation.run(async () => {
    const original = decisionsRef.current[pairing.pairing_id] || proposed;
    commitDecisions({ ...decisionsRef.current, [pairing.pairing_id]: original });
    setError(""); setNotice("");
    try {
      const result = await api(`/v1/admin/member-pairings/${encodeURIComponent(pairing.pairing_id)}/${original.action}`, { method: "POST", body: JSON.stringify(original.body) });
      if (result?.pairing_id !== pairing.pairing_id || result.state !== (original.action === "approve" ? "approved" : "rejected")) throw new Error("审批回执不完整");
      const remaining = { ...decisionsRef.current }; delete remaining[pairing.pairing_id]; commitDecisions(remaining);
      if (!mounted.current) return;
      setPairings((items) => items.map((item) => item.pairing_id === result.pairing_id ? result : item));
      setNotice(original.action === "approve" ? "已批准。成员客户端会自动接入并检查连接。" : "已拒绝此入组申请。");
      await onRefresh?.();
    } catch (failure) {
      // Known rejected writes can be corrected; ambiguous deliveries keep the
      // original choice frozen across refreshes and browser reloads.
      if ([400, 401, 403, 404, 409, 422].includes(failure.status)) { const remaining = { ...decisionsRef.current }; delete remaining[pairing.pairing_id]; commitDecisions(remaining); }
      if (mounted.current) { setError(decisionError(failure)); await refresh(); }
    }
  });
  const pending = pairings.filter((item) => item.state === "pending");
  return <section className="detail-section member-pairing-admin" aria-label="在线入组审批"><header><div><h2><UserRoundCheck size={18} /> 在线入组审批</h2><span>通过本人联系渠道核对；短码仅用于配对核对，不能代替身份。</span></div><button className="button small" disabled={mutation.busy} onClick={refresh}><RefreshCw size={15} />刷新入组申请</button></header>
    {!loaded && !error && <p role="status">正在读取入组申请…</p>}
    {loaded && !pending.length && <p>暂无待审批的入组申请。</p>}
    {pending.map((item) => <PairingReview key={item.pairing_id} pairing={item} users={users} ready={ready} busy={mutation.busy} decision={decisions[item.pairing_id]} onDecide={decide} onRead={refresh} />)}
    {error && <p className="form-error" role="alert">{error}</p>}{notice && <p className="member-notice" role="status">{notice}</p>}
  </section>;
}
