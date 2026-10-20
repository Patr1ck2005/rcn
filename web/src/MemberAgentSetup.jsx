import { useEffect, useRef, useState } from "react";
import { CheckCircle2, Download, KeyRound, RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "./api";
import { useMutationGuard } from "./useMutationGuard";
import { downloadMemberAgentBundle, memberAgentTargets, memberIdentityVerified, validateMemberAgentBundle } from "./memberAgentConfig";

export default function MemberAgentSetup({ session, onSession }) {
  const [target, setTarget] = useState("codex");
  const [agents, setAgents] = useState([]);
  const [selectedId, setSelectedId] = useState("new");
  const [agentId, setAgentId] = useState(() => crypto.randomUUID());
  const [label, setLabel] = useState("我的 Codex");
  const [agentToken, setAgentToken] = useState("");
  const [bundle, setBundle] = useState(null);
  const [error, setError] = useState("");
  const [checkFailed, setCheckFailed] = useState(false);
  const [identityConfirmed, setIdentityConfirmed] = useState(false);
  const [notice, setNotice] = useState("");
  const current = useRef(session);
  current.current = session;
  const mutation = useMutationGuard();
  const online = memberIdentityVerified(session) && !checkFailed;
  const selected = agents.find((item) => item.agent_id === selectedId);
  const needsToken = !selected?.configured;
  const refreshAgents = async () => {
    const value = await api("/local/v1/agent-configurations");
    setAgents(value.agents || []);
  };
  useEffect(() => { setBundle(null); setNotice(""); }, [session?.actor?.actor_id, session?.center_url, session?.online, session?.remote_actions_available]);
  useEffect(() => {
    setIdentityConfirmed(false); setCheckFailed(false); setSelectedId("new");
    setAgentId(crypto.randomUUID()); setAgentToken(""); setAgents([]);
    let active = true;
    api("/local/v1/agent-configurations").then((value) => { if (active) setAgents(value.agents || []); })
      .catch((failure) => { if (active) setError(failure.message); });
    return () => { active = false; };
  }, [session?.actor?.actor_id, session?.center_url]);
  const recheck = () => mutation.run(async () => {
    setError(""); setBundle(null); setNotice("");
    try {
      const verified = await api("/local/v1/session");
      onSession(verified);
      setCheckFailed(!memberIdentityVerified(verified));
      if (!memberIdentityVerified(verified)) throw new Error("个人身份或中心连接尚未确认，请重新登录或恢复网络后自检。");
      setNotice("中心已重新核验你的个人身份，可以生成 Agent 配置。");
    } catch (failure) { setCheckFailed(true); setError(failure.message); }
  });
  const generate = () => mutation.run(async () => {
    setError(""); setBundle(null); setNotice("");
    try {
      const body = { target, agent_id: agentId, label: label.trim(), ...(needsToken ? { token: agentToken.trim() } : {}) };
      const value = await api("/local/v1/agent-instructions", { method: "POST", body: JSON.stringify(body) });
      setBundle(validateMemberAgentBundle(value, current.current, target, agentId));
      setSelectedId(agentId);
      await refreshAgents();
      setNotice("配置已生成。下载后放入需要使用 RCN 的项目目录，再按接入说明引用。");
    } catch (failure) {
      if ([401, 403, 503].includes(failure.status)) setCheckFailed(true);
      setError(failure.message);
      await refreshAgents().catch(() => {});
    } finally { setAgentToken(""); }
  });
  const chooseAgent = (value) => {
    setSelectedId(value); setBundle(null); setNotice(""); setAgentToken("");
    const known = agents.find((item) => item.agent_id === value);
    if (known) { setAgentId(known.agent_id); setLabel(known.label); setTarget(known.target); }
    else { setAgentId(crypto.randomUUID()); setLabel(`我的 ${memberAgentTargets[target].label}`); }
  };
  const clearLogin = () => mutation.run(async () => {
    setError(""); setBundle(null); setNotice("");
    try {
      const result = await api(`/local/v1/agent-configurations/${agentId}`, { method: "DELETE" });
      if (!result.local_login_removed || result.center_token_revoked !== false) throw new Error("本机移除结果尚未确认，请刷新原实例。");
      await refreshAgents();
      setNotice("已移除此 Agent 的本机加密登录。中心 token 仍需管理员按原签发记录单独撤销。");
    } catch (failure) { setError(failure.message); }
  });
  return <main className="app-page member-page"><div className="page-title"><div><span>MEMBER / SETUP</span><h1>连接与 Agent 配置</h1><p>确认个人身份和中心连接，然后为你使用的 Agent 导出配置。</p></div></div>
    <section className="member-panel"><header><h2><KeyRound size={18} /> 1 · 确认个人身份</h2><span className="member-badge">{online ? "中心已核验" : "连接待确认"}</span></header>
      <dl className="member-metadata"><div><dt>个人身份</dt><dd>{session?.actor?.actor_id || "未登录"}</dd></div><div><dt>中心地址</dt><dd>{session?.configured_connection ? "管理员预配置的中心连接" : session?.center_url || "未连接"}</dd></div><div><dt>角色</dt><dd>{session?.actor?.roles?.join("、") || "由中心管理"}</dd></div></dl>
      <p>Agent 使用你的个人身份与跨项目限额，并持有独立的受限 token。管理员可按原签发记录单独撤销某个 Agent，不影响桌面登录或其他 Agent。</p>
      <label className="member-consent"><input type="checkbox" checked={identityConfirmed} disabled={!online || mutation.busy} onChange={(event) => { setIdentityConfirmed(event.target.checked); setBundle(null); }} /><span>我确认使用上方个人身份配置 Agent。</span></label>
    </section>
    <section className="member-panel"><header><h2><CheckCircle2 size={18} /> 2 · 连接自检</h2><span>{online ? "中心身份接口已响应" : "请恢复连接后重新自检"}</span></header>
      <p>自检会向中心重新核验当前登录。身份与连接通过后，才允许生成配置。</p><button className="button" disabled={mutation.busy} onClick={recheck}><RefreshCw size={16} />重新自检</button>
    </section>
    <section className="member-panel member-contribution-form"><header><h2>3 · 导出 Agent 配置</h2></header>
      <label>Agent 实例<select aria-label="Agent 实例" value={selectedId} disabled={mutation.busy} onChange={(event) => chooseAgent(event.target.value)}><option value="new">新建独立 Agent</option>
        {agents.map((item) => <option key={item.agent_id} value={item.agent_id}>{item.label} · {memberAgentTargets[item.target]?.label || item.target}{item.configured ? "" : " · 本机登录已移除"}</option>)}</select></label>
      <label>Agent 名称<input aria-label="Agent 名称" maxLength={80} value={label} disabled={mutation.busy || Boolean(selected)} onChange={(event) => setLabel(event.target.value)} /></label>
      <label>使用的 Agent<select aria-label="使用的 Agent" value={target} disabled={mutation.busy || Boolean(selected)} onChange={(event) => { setTarget(event.target.value); setLabel(`我的 ${memberAgentTargets[event.target.value].label}`); setAgentId(crypto.randomUUID()); setAgentToken(""); setBundle(null); setNotice(""); }}>
        {Object.entries(memberAgentTargets).map(([value, item]) => <option key={value} value={value}>{item.label}</option>)}</select></label>
      {needsToken && <label>独立 Agent token<input aria-label="独立 Agent token" type="password" autoComplete="off" value={agentToken} disabled={mutation.busy || !online} onChange={(event) => setAgentToken(event.target.value)} /></label>}
      <p>首次配置需请管理员签发一份属于你、带 agent scope 的独立 token。不要粘贴桌面登录 token，也不要在不同实例间复用。</p>
      {selected?.credential_id && <p>中心凭据 ID：<code>{selected.credential_id}</code>。请把此 ID 提供给管理员以单独撤销该 Agent。</p>}
      <p>配置不包含个人 token。它引用此 Agent 专属目录的加密登录和已安装客户端；仅供这台电脑的当前 Windows 用户使用。重复导出原实例不再签发凭据。</p>
      <p>下载并解压后，将接入说明中的引用加入项目现有的 <code>{memberAgentTargets[target].entry}</code>，保留原有项目规则。</p>
      <div className="member-actions"><button className="button button-primary" disabled={mutation.busy || !online || !identityConfirmed || !label.trim() || (needsToken && !agentToken.trim())} onClick={generate}>{mutation.busy ? "正在核验与生成…" : `生成 ${memberAgentTargets[target].label} 配置`}</button>
        {bundle && <button className="button" onClick={() => downloadMemberAgentBundle(bundle)}><Download size={16} />下载配置 ZIP</button>}
        {selected?.configured && <button className="button" disabled={mutation.busy} onClick={clearLogin}>移除此 Agent 的本机登录</button>}</div>
      {bundle && <details className="member-bindings"><summary>查看接入说明</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{bundle.setup_instructions}</pre></details>}
      {error && <div className="form-error" role="alert">{error}</div>}{notice && <p className="member-notice" role="status">{notice}</p>}
    </section><div className="member-actions"><Link className="button" to="/app/submit">继续提交任务</Link><Link className="button" to="/app/contribution">可选：贡献我的电脑</Link></div>
  </main>;
}
