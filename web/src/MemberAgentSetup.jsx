import { useEffect, useRef, useState } from "react";
import { CheckCircle2, Copy, Download, KeyRound, RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "./api";
import { useMutationGuard } from "./useMutationGuard";
import { connectionError } from "./memberConnectionModel";
import { downloadMemberAgentBundle, memberAgentTargets, memberIdentityVerified, validateMemberAgentBundle } from "./memberAgentConfig";

export default function MemberAgentSetup({ session, onSession, doctor, onCheck, checking = false, embedded = false }) {
  const [target, setTarget] = useState("codex");
  const [agents, setAgents] = useState([]);
  const [selectedId, setSelectedId] = useState("new");
  const [agentId, setAgentId] = useState(() => crypto.randomUUID());
  const [label, setLabel] = useState("我的 Codex");
  const [bundle, setBundle] = useState(null);
  const [error, setError] = useState("");
  const [checkFailed, setCheckFailed] = useState(false);
  const [identityConfirmed, setIdentityConfirmed] = useState(false);
  const [notice, setNotice] = useState("");
  const [revokeConfirmed, setRevokeConfirmed] = useState(false);
  const [unknownExportId, setUnknownExportId] = useState(null);
  const [readingExisting, setReadingExisting] = useState(false);
  const bundleRequest = useRef(0);
  const selection = useRef("new");
  const current = useRef(session);
  current.current = session;
  const mutation = useMutationGuard();
  const online = memberIdentityVerified(session) && !checkFailed;
  const selected = agents.find((item) => item.agent_id === selectedId);
  const revoked = Boolean(selected?.revoked || selected?.center_token_revoked || selected?.revoked_at || selected?.state === "revoked" || selected?.registration_state === "revoked");
  const canReadExisting = Boolean(selected?.configured && !revoked
    && (!selected.registration_state || selected.registration_state === "confirmed"));
  const refreshAgents = async () => {
    const value = await api("/local/v1/agent-configurations");
    setAgents(value.agents || []);
  };
  useEffect(() => { bundleRequest.current += 1; setBundle(null); setNotice(""); }, [session?.actor?.actor_id, session?.center_url, session?.online, session?.remote_actions_available]);
  useEffect(() => () => { bundleRequest.current += 1; }, []);
  useEffect(() => {
    if (!doctor) return;
    const failed = doctor.checks?.some((item) => item.status === "failed" && /identity|session|credential|auth|center|channel|transport|connection/.test(item.stage));
    setCheckFailed(Boolean(failed));
    if (failed) setBundle(null);
  }, [doctor]);
  useEffect(() => {
    setIdentityConfirmed(false); setCheckFailed(false); setSelectedId("new");
    selection.current = "new";
    setAgentId(crypto.randomUUID()); setAgents([]); setRevokeConfirmed(false); setUnknownExportId(null);
    let active = true;
    api("/local/v1/agent-configurations").then((value) => { if (active) setAgents(value.agents || []); })
      .catch((failure) => { if (active) setError(connectionError(failure)); });
    return () => { active = false; };
  }, [session?.actor?.actor_id, session?.center_url]);
  const recheck = () => mutation.run(async () => {
    setError(""); setBundle(null); setNotice("");
    try {
      if (onCheck) { await onCheck(); return; }
      const verified = await api("/local/v1/session");
      onSession(verified);
      setCheckFailed(!memberIdentityVerified(verified));
      if (!memberIdentityVerified(verified)) throw new Error("个人身份或中心连接尚未确认，请重新登录或恢复网络后自检。");
      setNotice("中心已重新核验你的个人身份，可以生成 Agent 配置。");
    } catch (failure) { setCheckFailed(true); setError(connectionError(failure)); }
  });
  const generate = () => mutation.run(async () => {
    if (!online || !identityConfirmed || revoked) return;
    setError(""); setBundle(null); setNotice("");
    try {
      const body = { target, agent_id: agentId, label: label.trim() };
      const value = await api("/local/v1/agent-instructions", { method: "POST", body: JSON.stringify(body) });
      setBundle(validateMemberAgentBundle(value, current.current, target, agentId));
      selection.current = agentId;
      setSelectedId(agentId);
      await refreshAgents();
      setNotice("Agent 配置已生成，独立凭据已由客户端安全登记。复制接入说明或下载配置包，交给本机 Agent 完成项目接入。");
    } catch (failure) {
      if ([401, 403, 503].includes(failure.status)) setCheckFailed(true);
      setError(connectionError(failure));
      await refreshAgents().catch(() => {});
    }
  });
  const readExisting = (known) => mutation.run(async () => {
    if (!online || !known?.configured || !memberAgentTargets[known.target]
      || known.registration_state && known.registration_state !== "confirmed"
      || known.revoked || known.center_token_revoked || known.revoked_at || known.state === "revoked") return;
    const request = ++bundleRequest.current;
    const original = { target: known.target, agent_id: known.agent_id, label: known.label };
    setReadingExisting(true); setError(""); setBundle(null); setNotice("");
    try {
      // Re-export the selected confirmed profile through the existing endpoint.
      // Its persisted ID/label/target bind the original credential; no token or
      // new UUID is generated for reopening, copying or retrying this export.
      const value = await api("/local/v1/agent-instructions", { method: "POST", body: JSON.stringify(original) });
      if (request !== bundleRequest.current || selection.current !== original.agent_id) return;
      setBundle(validateMemberAgentBundle(value, current.current, original.target, original.agent_id));
      setUnknownExportId(null);
      setNotice("已读取此 Agent 的原配置，可直接复制接入说明或下载配置包；独立凭据与实例编号保持原值。");
    } catch (failure) {
      if (request !== bundleRequest.current || selection.current !== original.agent_id) return;
      const unknown = !failure.status || failure.status >= 500;
      setUnknownExportId(unknown ? original.agent_id : null);
      if ([401, 403].includes(failure.status)) setCheckFailed(true);
      setError(`${connectionError(failure)}${unknown ? " 原 Agent 编号已保留，请重新读取此实例的接续说明。" : ""}`);
    } finally { setReadingExisting(false); }
  });
  const chooseAgent = (value) => {
    if (mutation.busy || value === "new" && unknownExportId) return;
    bundleRequest.current += 1; selection.current = value;
    setSelectedId(value); setBundle(null); setNotice(""); setRevokeConfirmed(false);
    const known = agents.find((item) => item.agent_id === value);
    if (known) {
      setAgentId(known.agent_id); setLabel(known.label); setTarget(known.target);
      void readExisting(known);
    }
    else { setAgentId(crypto.randomUUID()); setLabel(`我的 ${memberAgentTargets[target].label}`); }
  };
  const clearLogin = () => mutation.run(async () => {
    setError(""); setBundle(null); setNotice("");
    try {
      const result = await api(`/local/v1/agent-configurations/${encodeURIComponent(agentId)}`, { method: "DELETE" });
      if (!result.local_login_removed || result.center_token_revoked !== false) throw new Error("本机移除结果尚未确认，请刷新原实例。");
      await refreshAgents();
      setNotice("已移除此 Agent 的本机加密登录。中心凭据仍有效；如需停用，请单独撤销中心凭据。");
    } catch (failure) { setError(connectionError(failure)); }
  });
  const revoke = () => mutation.run(async () => {
    if (!revokeConfirmed || !selected) return;
    setError(""); setBundle(null); setNotice("");
    try {
      const result = await api(`/local/v1/agent-configurations/${encodeURIComponent(agentId)}/revoke`, { method: "POST", body: "{}" });
      if (result.center_token_revoked !== true && result.revoked !== true && result.state !== "revoked") throw new Error("中心撤销结果尚未确认，请刷新原实例；不要重新生成其他凭据。");
      await refreshAgents(); setRevokeConfirmed(false); setNotice("此 Agent 的中心凭据已撤销，桌面个人登录和其他 Agent 不受影响。");
    } catch (failure) { setError(`${connectionError(failure)} 请读取原实例确认撤销结果。`); await refreshAgents().catch(() => {}); }
  });
  const copyInstructions = async () => {
    try { await navigator.clipboard.writeText(bundle.setup_instructions); setNotice("接入说明已复制，可直接交给本机 Agent。"); }
    catch { setError("复制未完成，请展开接入说明手动复制，或下载配置 ZIP。"); }
  };
  const Wrapper = embedded ? "section" : "main";
  return <Wrapper className={embedded ? "member-agent-setup" : "app-page member-page"}>{!embedded && <div className="page-title"><div><span>MEMBER / SETUP</span><h1>连接与 Agent 配置</h1><p>确认个人身份和中心连接，然后为你使用的 Agent 导出配置。</p></div></div>}
    <section className="member-panel"><header><h2><KeyRound size={18} /> {embedded ? "当前个人身份" : "1 · 确认个人身份"}</h2><span className="member-badge">{online ? "中心已核验" : "连接待确认"}</span></header>
      <dl className="member-metadata"><div><dt>个人身份</dt><dd>{session?.actor?.actor_id || "未登录"}</dd></div><div><dt>中心地址</dt><dd>{session?.configured_connection ? "管理员预配置的中心连接" : session?.center_url || "未连接"}</dd></div><div><dt>角色</dt><dd>{session?.actor?.roles?.join("、") || "由中心管理"}</dd></div></dl>
      <p>Agent 使用你的个人身份与跨项目限额。配置时自动登记独立受限凭据，无需输入第二份 token；每个 Agent 可单独撤销。</p>
      <label className="member-consent"><input type="checkbox" checked={identityConfirmed} disabled={!online || mutation.busy} onChange={(event) => { setIdentityConfirmed(event.target.checked); if (!selected?.configured) setBundle(null); }} /><span>我确认使用上方个人身份配置 Agent。</span></label>
    </section>
    {!embedded && <section className="member-panel"><header><h2><CheckCircle2 size={18} /> 2 · 连接自检</h2><span>{online ? "中心身份接口已响应" : "请恢复连接后重新自检"}</span></header>
      <p>自检会向中心重新核验当前登录。身份与连接通过后，才允许生成配置。</p><button className="button" disabled={mutation.busy} onClick={recheck}><RefreshCw size={16} />重新自检</button>
    </section>}
    <section className="member-panel member-contribution-form"><header><h2>{embedded ? "2 · 一键配置 Agent" : "3 · 导出 Agent 配置"}</h2></header>
      <label>Agent 实例<select aria-label="Agent 实例" value={selectedId} disabled={mutation.busy} onChange={(event) => chooseAgent(event.target.value)}><option value="new" disabled={Boolean(unknownExportId)}>新建独立 Agent</option>
        {agents.map((item) => <option key={item.agent_id} value={item.agent_id}>{item.label} · {memberAgentTargets[item.target]?.label || item.target}{item.revoked || item.center_token_revoked || item.revoked_at || item.state === "revoked" || item.registration_state === "revoked" ? " · 已撤销" : item.configured ? "" : " · 本机登录已移除"}</option>)}</select></label>
      <label>Agent 名称<input aria-label="Agent 名称" maxLength={80} value={label} disabled={mutation.busy || Boolean(selected)} onChange={(event) => setLabel(event.target.value)} /></label>
      <label>使用的 Agent<select aria-label="使用的 Agent" value={target} disabled={mutation.busy || Boolean(selected)} onChange={(event) => { const next = event.target.value; setTarget(next); if (!label.trim() || label === `我的 ${memberAgentTargets[target].label}`) setLabel(`我的 ${memberAgentTargets[next].label}`); setAgentId(crypto.randomUUID()); setBundle(null); setNotice(""); }}>
        {Object.entries(memberAgentTargets).map(([value, item]) => <option key={value} value={value}>{item.label}</option>)}</select></label>
      <p>当前范围仅限本人的已授权项目和提交额度。贡献计算为独立可选步骤，既有机器暂停设置保持原状。</p>
      {selected && <p>Agent 实例编号：<code>{selected.agent_id}</code></p>}
      {selected?.credential_id && <p>中心凭据 ID：<code>{selected.credential_id}</code>{revoked ? "（已撤销）" : "（可单独撤销）"}</p>}
      <p>配置不包含个人 token。它引用此 Agent 专属目录的加密登录和已安装客户端；仅供这台电脑的当前 Windows 用户使用。重复导出原实例不再签发凭据。</p>
      <p>下载并解压后，将接入说明中的引用加入项目现有的 <code>{memberAgentTargets[target].entry}</code>，保留原有项目规则。</p>
      <div className="member-actions"><button className="button button-primary" disabled={mutation.busy || checking || !online || !canReadExisting && (!identityConfirmed || !label.trim()) || revoked} onClick={canReadExisting ? () => readExisting(selected) : generate}>{readingExisting ? "正在读取原 Agent 配置…" : mutation.busy ? "正在核验与生成…" : canReadExisting ? "重新读取接续说明" : `生成 ${memberAgentTargets[target].label} 配置`}</button>
        {bundle && <button className="button" disabled={mutation.busy} onClick={copyInstructions}><Copy size={16} />复制接入说明</button>}
        {bundle && <button className="button" disabled={mutation.busy} onClick={() => downloadMemberAgentBundle(bundle)}><Download size={16} />下载配置 ZIP</button>}
        {selected?.configured && <button className="button" disabled={mutation.busy} onClick={clearLogin}>移除此 Agent 的本机登录</button>}</div>
      {bundle && <details className="member-bindings"><summary>查看接入说明</summary><pre className="member-instructions">{bundle.setup_instructions}</pre></details>}
      {selected && !revoked && <details className="member-bindings member-revoke"><summary>停用此 Agent</summary><p>撤销中心凭据会阻止此 Agent 后续访问中心。本机登录移除与中心撤销是两个独立操作。</p><label className="member-consent"><input type="checkbox" checked={revokeConfirmed} disabled={mutation.busy || !online} onChange={(event) => setRevokeConfirmed(event.target.checked)} /><span>确认撤销 {selected.label} 的独立中心凭据。</span></label><button className="button" disabled={mutation.busy || !online || !revokeConfirmed} onClick={revoke}>撤销此 Agent 的中心凭据</button></details>}
      {selected && <button className="button small" disabled={mutation.busy} onClick={() => mutation.run(async () => { try { await refreshAgents(); } catch (failure) { setError(connectionError(failure)); } })}>刷新此 Agent 状态</button>}
      {error && <div className="form-error" role="alert">{error}</div>}{notice && <p className="member-notice" role="status">{notice}</p>}
    </section>{!embedded && <div className="member-actions"><Link className="button" to="/app/submit">继续提交任务</Link><Link className="button" to="/app/contribution">可选：贡献我的电脑</Link></div>}
  </Wrapper>;
}
