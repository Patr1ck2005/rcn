import { useMutationGuard } from "./useMutationGuard";
import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";
import { ArrowRight, BookOpen, Boxes, CheckCircle2, Cpu, Download, FolderOpen, Gauge, KeyRound, LogOut, Menu, Network, Pause, Play, RefreshCw, Upload, X } from "lucide-react";
import { Link, Navigate, NavLink, Route, Routes, useLocation, useNavigate } from "react-router-dom";

import { api } from "./api";
import { MyPersonalAccess } from "./PersonalAccess";
import MemberAgentSetup from "./MemberAgentSetup";
import { usePageRefresh } from "./usePageRefresh";
import { DATA_REFRESH_EVENT, watchPageReturn } from "./freshness";
import { HelpCenter } from "./HelpSystem";
import { mutateAndRecover, operationActions, operationLabel, requiresUnitCount, validateUnitCount } from "./memberClientModel";
import { contributionScope, contributionNotFound, loadContributionCheckpoints, saveContributionCheckpoints, readContributionOriginal, submitContribution } from "./memberContributionCheckpoint";
import "./memberClient.css";

const ClusterInsights = lazy(() => import("./ClusterInsights"));
const JobDetail = lazy(() => import("./JobDetail"));
const bytes = (value) => value == null || !Number.isFinite(Number(value)) ? "未知" : Number(value) < 1024 * 1024
  ? `${(Number(value) / 1024).toLocaleString("zh-CN", { maximumFractionDigits: 1 })} KiB`
  : `${(Number(value) / 1024 / 1024).toLocaleString("zh-CN", { maximumFractionDigits: 1 })} MiB`;
const sessionActor = (session) => session?.actor || {};
const previewOf = (value) => value?.preview || {};
const errorMessage = (error) => error.status === 401 ? "个人登录已失效，请重新连接中心。" : error.message;

function MemberBrand() {
  return <Link className="brand brand-compact" to="/app/submit"><span className="brand-mark"><Network size={18} /></span><span><strong>RCN 成员客户端</strong><small>科研任务与我的计算节点</small></span></Link>;
}

export default function MemberClient({ capabilities }) {
  const [session, setSession] = useState(null);
  const [error, setError] = useState("");
  const [navOpen, setNavOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();
  const mutation = useMutationGuard();
  const refreshSession = usePageRefresh(async ({ signal, isCurrent }) => {
    try {
      const value = await api("/local/v1/session", { signal });
      if (isCurrent()) { setSession(value); setError(""); }
    } catch (failure) { if (isCurrent()) setError(errorMessage(failure)); }
    finally { if (isCurrent()) setLoading(false); }
  }, { initial: true, intervalMs: 15000, listen: false });
  useEffect(() => watchPageReturn(() => { void refreshSession(); window.dispatchEvent(new Event(DATA_REFRESH_EVENT)); }), [refreshSession]);
  const logout = () => mutation.run(async () => {
    try { await api("/local/v1/session", { method: "DELETE" }); setSession((previous) => ({ ...previous, connected: false, actor: null })); navigate("/connect"); }
    catch (failure) { setError(errorMessage(failure)); }
  });
  if (loading) return <main className="member-loading" role="status">正在读取本机客户端状态…</main>;
  if (!session?.connected) return <MemberConnect session={session} error={error} onRetry={refreshSession} onConnect={(value) => { setSession(value); navigate("/app/setup"); }} />;
  const actor = sessionActor(session);
  const online = session.online !== false && session.remote_actions_available !== false;
  return <div className="app-shell member-client"><aside className={`app-nav${navOpen ? " open" : ""}`}>
    <MemberBrand /><nav>
      <NavLink to="/app/setup" onClick={() => setNavOpen(false)}><KeyRound size={18} />连接与 Agent 配置</NavLink>
      <NavLink to="/app/submit" onClick={() => setNavOpen(false)}><Upload size={18} />提交任务</NavLink>
      <NavLink to="/app/runs" end onClick={() => setNavOpen(false)}><Boxes size={18} />我的任务</NavLink>
      <NavLink to="/app/contribution" onClick={() => setNavOpen(false)}><Cpu size={18} />贡献计算</NavLink>
      <NavLink to="/app/overview" onClick={() => setNavOpen(false)}><Gauge size={18} />集群总览</NavLink>
      <NavLink to="/app/help" onClick={() => setNavOpen(false)}><BookOpen size={18} />帮助与文档</NavLink>
    </nav><div className="nav-account"><div><span>{actor.actor_id || actor.user_id || "已连接"}</span><small>个人身份 · {capabilities.client_version || "成员客户端"}</small></div><button title="退出个人登录" aria-label="退出个人登录" disabled={mutation.busy} onClick={logout}><LogOut size={17} /></button></div>
  </aside><section className="app-workspace"><header className="workspace-header">
    <button className="nav-toggle" aria-label="打开导航" aria-expanded={navOpen} onClick={() => setNavOpen(!navOpen)}><Menu size={19} /></button>
    <div className={`member-center${online ? "" : " offline"}`}><CheckCircle2 size={16} /><span>{online ? "中心已连接" : "中心连接未确认"}</span><small>{session.configured_connection ? "管理员预配置的中心连接" : session.center_url}</small></div>
    <button className="icon-button" aria-label="刷新连接" onClick={() => { void refreshSession(); window.dispatchEvent(new Event(DATA_REFRESH_EVENT)); }}><RefreshCw size={17} /></button>
  </header>{error && <div className="inline-error" role="alert">{error}</div>}
    {!online && <div className="member-offline" role="status"><b>当前离线，保留本机身份与提交记录。</b><p>{session.connection_error?.message || "可以查看本机记录或暂停自己的计算。提交、上传、下载与恢复接活需要重新连接中心。"}</p><Link to="/app/contribution">管理本机计算与暂停</Link></div>}
    <Suspense fallback={<main className="member-loading" role="status">正在加载…</main>}><Routes>
      <Route path="/connect" element={<Navigate to="/app/setup" replace />} />
      <Route path="/app/setup" element={<MemberAgentSetup session={session} onSession={setSession} />} />
      <Route path="/app/submit" element={<MemberSubmission actor={actor} online={online} />} />
      <Route path="/app/runs" element={<MemberOperations online={online} />} />
      <Route path="/app/runs/:jobId" element={<JobDetail />} />
      <Route path="/app/contribution" element={<MemberContribution key={`${actor.actor_id}:${session.center_url}`} session={session} online={online} />} />
      <Route path="/app/overview" element={<main className="app-page"><ClusterInsights /></main>} />
      <Route path="/app/help" element={<HelpCenter embedded />} />
      <Route path="/app/help/:slug" element={<HelpCenter embedded />} />
      <Route path="/help/*" element={<Navigate to="/app/help" replace />} />
      <Route path="*" element={<Navigate to="/app/submit" replace state={{ from: location.pathname }} />} />
    </Routes></Suspense>
  </section></div>;
}

function MemberConnect({ session, error: externalError, onRetry, onConnect }) {
  const configured = ["https", "managed-ssh"].includes(session?.configured_connection?.mode)
    ? session.configured_connection : null;
  const [center, setCenter] = useState(session?.center_url?.startsWith("https://") ? session.center_url : "");
  const [personalToken, setPersonalToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const mutation = useMutationGuard();
  const submit = (event) => mutation.run(async () => {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const connected = await api("/local/v1/session", { method: "POST", body: JSON.stringify({ center_url: configured?.center_reference || center.trim(), token: personalToken.trim() }) });
      setPersonalToken(""); onConnect(connected);
    } catch (failure) { setError(errorMessage(failure)); }
    finally { setBusy(false); }
  }, event);
  return <div className="connect-page member-client"><header className="public-header"><MemberBrand /><span className="member-badge">本机客户端</span></header><main className="connect-main">
    <section><div className="eyebrow"><KeyRound size={16} />个人身份</div><h1>连接课题组计算中心</h1><p>使用个人登录信息提交获授权项目的任务。登录信息由本机客户端加密保存。</p>
      <form onSubmit={submit}>{configured
        ? <label>管理员预配置的中心连接<input value="课题组计算中心" readOnly /></label>
        : <label>中心 HTTPS 地址<input type="url" name="center_url" value={center} onChange={(event) => setCenter(event.target.value)} placeholder="https://compute.example.org" pattern="https://.*" required autoComplete="url" /></label>}
        <label>个人访问 token<input type="password" name="personal_token" value={personalToken} onChange={(event) => setPersonalToken(event.target.value)} required autoComplete="off" /></label>
        {(error || externalError) && <div className="form-error" role="alert">{error || externalError}</div>}
        <button className="button button-primary" disabled={busy}><KeyRound size={16} />{busy ? "正在连接" : "连接并进入"}</button>
      </form>{externalError && <button className="button small" onClick={onRetry}>恢复本机连接</button>}
    </section><aside><h2>安装后的两个入口</h2><dl><div><dt>提交任务</dt><dd>导入项目侧准备的任务包，查看进度并下载核验结果。</dd></div><div><dt>贡献计算（可选）</dt><dd>另行使用私密机器邀请接入，设置资源预算、允许时间和暂停。</dd></div></dl></aside>
  </main></div>;
}

function PackagePreview({ preview, filename }) {
  return <section className="member-panel member-preview"><header><h2>任务包预览</h2><span>{filename}</span></header><dl className="member-metadata">
    <div><dt>项目</dt><dd>{preview.project_id || "未提供"}</dd></div><div><dt>执行 Profile</dt><dd>{preview.profile_id || "未提供"}</dd></div>
    <div><dt>提交身份</dt><dd>{preview.submitter_id || preview.user_id || "由中心核验"}</dd></div><div><dt>输入文件</dt><dd>{preview.input_count ?? "未知"} 个 · {bytes(preview.total_bytes)}</dd></div>
    <div><dt>计算单元</dt><dd>{preview.unit_count ?? "需要补充分包信息"}</dd></div><div><dt>申报串行耗时</dt><dd>{preview.estimated_duration_seconds == null ? "未知" : `${preview.estimated_duration_seconds} 秒`}</dd></div>
  </dl>{preview.output_contract && <p>输出合同：<code>{typeof preview.output_contract === "string" ? preview.output_contract : preview.output_contract.output_contract_id || "已绑定"}</code></p>}
    {(preview.output_contract_sha256 || preview.package_contents_sha256) && <details className="member-bindings"><summary>任务包绑定信息</summary>{preview.output_contract_sha256 && <p>输出合同 SHA-256：<code>{preview.output_contract_sha256}</code></p>}{preview.package_contents_sha256 && <p>任务包内容 SHA-256：<code>{preview.package_contents_sha256}</code></p>}</details>}
  </section>;
}

function MemberSubmission({ actor, online }) {
  const [selected, setSelected] = useState(null);
  const [operation, setOperation] = useState(null);
  const [unitCount, setUnitCount] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const mutation = useMutationGuard();
  const operationId = useRef(null);
  const importPackage = (event) => mutation.run(async () => {
    const file = event.target.files?.[0];
    if (!file) return;
    setBusy("import"); setError(""); setSelected(null); setOperation(null); operationId.current = null;
    try {
      const imported = await api("/local/v1/packages", { method: "POST", headers: { "Content-Type": "application/zip", "X-RCN-Filename": encodeURIComponent(file.name) }, body: file });
      setSelected(imported); setUnitCount(""); setOperation(imported.operation || null);
      operationId.current = imported.operation_id || crypto.randomUUID();
    } catch (failure) { setError(errorMessage(failure)); }
    finally { setBusy(""); event.target.value = ""; }
  }, event);
  const plan = (event) => mutation.run(async () => {
    event.preventDefault();
    if (!online) return;
    setBusy("plan"); setError("");
    try {
      const body = { package_id: selected.package_id };
      if (requiresUnitCount(previewOf(selected))) body.requested_unit_count = validateUnitCount(unitCount);
      setOperation(await api(`/local/v1/operations/${operationId.current}`, { method: "PUT", body: JSON.stringify(body) }));
    } catch (failure) {
      if (!failure.status || failure.status >= 500) {
        try { setOperation(await api(`/local/v1/operations/${operationId.current}`)); }
        catch { setError(`${errorMessage(failure)}。原提交编号已保留，再次生成预览会恢复同一记录。`); }
      } else setError(errorMessage(failure));
    }
    finally { setBusy(""); }
  }, event);
  return <main className="app-page member-page"><div className="page-title"><div><span>MEMBER / SUBMIT</span><h1>提交科研任务</h1><p>导入 Workbench 准备的任务包，按原提交记录上传、计算和回收。</p></div></div>
    <MyPersonalAccess enabled={online} />
    <ol className="member-steps" aria-label="提交流程"><li className={!selected ? "current" : "done"}>选择任务包</li><li className={selected && !operation ? "current" : operation ? "done" : ""}>校验与预览</li><li className={operation ? "current" : ""}>确认、上传与计算</li><li>下载核验结果</li></ol>
    <section className="member-panel member-import"><div><FolderOpen size={24} /><h2>选择任务 ZIP</h2><p>任务包应绑定你的个人身份、获授权项目、执行 Profile 和输出合同。</p></div><label className={`button button-primary member-file-button${busy ? " disabled" : ""}`}><Upload size={16} />{busy === "import" ? "正在导入与核验" : "选择任务包"}<input aria-label="选择任务包" type="file" accept=".zip,application/zip" onChange={importPackage} disabled={Boolean(busy)} /></label></section>
    {error && <div className="inline-error" role="alert">{error}</div>}
    {selected && <PackagePreview preview={previewOf(selected)} filename={selected.filename} />}
    {selected && !operation && <form className="member-panel member-plan" onSubmit={plan}>
      {requiresUnitCount(previewOf(selected)) && <><h2>补充分包信息</h2><p>任务包没有可用的耗时与分包信息，请明确本次要生成的计算单元数。</p><label>请求计算单元数<input type="number" min="1" step="1" required value={unitCount} onChange={(event) => setUnitCount(event.target.value)} /></label></>}
      <p>中心将核验 {actor.actor_id || actor.user_id || "当前身份"} 的项目提交权及执行环境。</p><button className="button button-primary" disabled={Boolean(busy) || !online}><ArrowRight size={16} />{busy === "plan" ? "正在生成提交预览" : "生成提交预览"}</button>
    </form>}
    {operation && <OperationCard operation={operation} onChange={setOperation} online={online} />}
  </main>;
}

function useOperationRefresh(operation, onChange, online) {
  const id = operation.operation_id;
  const refreshNeeded = !operationActions(operation).verified && (Boolean(operation.job_id)
    || ["planning-unknown", "confirm-unknown"].includes(operation.phase));
  usePageRefresh(async ({ signal, isCurrent }) => {
    try { const updated = await api(`/local/v1/operations/${encodeURIComponent(id)}`, { signal }); if (isCurrent()) onChange(updated); }
    catch { /* An explicit action reports errors; polls retain the saved operation. */ }
  }, { key: id, intervalMs: 5000, enabled: Boolean(id && refreshNeeded && online) });

}

function OperationCard({ operation, onChange, online }) {
  const [busy, setBusy] = useState("");
  const mutation = useMutationGuard();
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [rerunOpen, setRerunOpen] = useState(false);
  const actions = operationActions(operation);
  useOperationRefresh(operation, onChange, online);
  const runAction = (action) => mutation.run(async () => {
    if (!online && action !== "collection/pause") return;
    setBusy(action); setError(""); setNotice("");
    try {
      const updated = action === "refresh" ? await api(`/local/v1/operations/${operation.operation_id}`)
        : await mutateAndRecover(api, operation.operation_id, action);
      onChange(updated); setNotice(updated.recovery_notice || (action === "confirm" && actions.hasJob ? "已核对原 Job，未新建任务。" : ""));
    } catch (failure) { setError(errorMessage(failure)); }
    finally { setBusy(""); }
  });
  const rerun = () => mutation.run(async () => {
    if (!online) return;
    setBusy("rerun"); setError("");
    const newId = crypto.randomUUID();
    try { onChange(await api(`/local/v1/operations/${operation.operation_id}/rerun`, { method: "POST", body: JSON.stringify({ operation_id: newId }) })); setRerunOpen(false); setNotice("已生成新的提交预览，请核对后确认。"); }
    catch (failure) {
      if (!failure.status || failure.status >= 500) {
        try { onChange(await api(`/local/v1/operations/${newId}`)); setRerunOpen(false); setNotice("已恢复新的提交预览，请核对后确认。"); }
        catch { setError(`${errorMessage(failure)}。请先到“我的任务”恢复查询，新的提交尚未确认。`); }
      } else setError(errorMessage(failure));
    }
    finally { setBusy(""); }
  });
  const jobId = operation.job_id || operation.job?.job_id;
  return <article className="member-panel member-operation" data-operation-id={operation.operation_id}>
    <header><div><h2>{previewOf(operation).project_id || "科研任务"}</h2><small>提交记录 <code>{operation.operation_id}</code></small></div><span className="member-badge">{operationLabel(operation)}</span></header>
    {operation.preview && <dl className="member-metadata"><div><dt>执行 Profile</dt><dd>{operation.preview.profile_id || "待核验"}</dd></div><div><dt>计算单元</dt><dd>{operation.preview.unit_count ?? operation.requested_unit_count ?? "待核验"}</dd></div></dl>}
    {jobId && <p>Job：<Link className="member-job-link" to={`/app/runs/${encodeURIComponent(jobId)}`}>{jobId}</Link></p>}
    {operation.job && <p className="member-progress-text">计算进度：{operation.job.completed_units ?? "未知"} / {operation.job.total_units ?? "未知"} 单元</p>}
    {operation.upload && <TransferProgress title="输入上传" progress={operation.upload} />}
    {operation.collection && <TransferProgress title="结果下载与核验" progress={operation.collection} />}
    {operation.collection_control?.state === "retry_wait" && <p className="member-notice" role="status">连接或存储暂时不可用，后台将自动续传原任务，已核验文件会保留。</p>}
    {operation.collection_control?.state === "user_paused" && <p className="member-notice" role="status">下载已暂停，断点保留。点击“下载并核验结果”继续原任务。</p>}
    {actions.canPauseCollection && <button className="button" disabled={Boolean(busy)} onClick={() => runAction("collection/pause")}><Pause size={16} />暂停结果下载</button>}
    {actions.verified && operation.collection?.directory && <div className="member-result" role="status"><CheckCircle2 size={18} /><div><b>结果已下载并通过校验</b><p>本机目录：<code>{operation.collection.directory}</code></p><small>科研数据集的正式导入由项目侧 Workbench 完成。</small></div></div>}
    {(error || operation.error?.message) && <div className="inline-error" role="alert">{error || operation.error.message}</div>}
    {notice && <p className="member-notice" role="status">{notice}</p>}
    <fieldset className="member-actions member-action-group" disabled={!online} aria-label="任务操作">
      {actions.canConfirm && <button className="button button-primary" disabled={Boolean(busy)} onClick={() => runAction("confirm")}><CheckCircle2 size={16} />{busy === "confirm" ? "正在确认" : "确认提交"}</button>}
      {actions.canUpload && <button className="button button-primary" disabled={Boolean(busy)} onClick={() => runAction("upload")}><Upload size={16} />{busy === "upload" ? "正在恢复上传" : "上传 / 继续上传"}</button>}
      {actions.canCollect && <button className="button button-primary" disabled={Boolean(busy)} onClick={() => runAction("collect")}><Download size={16} />{busy === "collect" ? "正在启动下载" : "下载并核验结果"}</button>}
      <button className="button" disabled={Boolean(busy)} onClick={() => runAction("refresh")}><RefreshCw size={15} />恢复查询</button>
      {actions.hasJob && <button className="button" disabled={Boolean(busy)} onClick={() => runAction("confirm")}>核对原提交</button>}
      {actions.hasJob && <button className="button" disabled={Boolean(busy)} onClick={() => setRerunOpen(true)}>重新计算…</button>}
    </fieldset>
    {rerunOpen && <div className="member-rerun" role="group" aria-label="确认重新计算"><b>重新计算将生成新的提交编号。</b><p>原任务及结果保留。仅恢复断线或查询进度时，请使用“恢复查询”。</p><div className="member-actions"><button className="button button-primary" disabled={Boolean(busy) || !online} onClick={rerun}>生成新提交预览</button><button className="button" onClick={() => setRerunOpen(false)}><X size={15} />返回原任务</button></div></div>}
  </article>;
}

function TransferProgress({ title, progress }) {
  const completed = progress.verified_files ?? progress.completed_units ?? progress.completed_files;
  const total = progress.total_units ?? progress.total_files;
  const noun = progress.total_units != null || progress.unit === "unit" ? "单元" : "文件";
  const fraction = completed != null && total > 0 ? Math.max(0, Math.min(1, completed / total)) : null;
  const transferState = progress.stage || progress.state;
  const states = { complete: "完成", completed: "完成", verified: "校验通过", uploading: "正在上传", collecting: "正在下载", planned: "等待开始", prepare: "正在准备", uploaded: "已上传", preparing: "正在校验源文件", downloading: "正在续传文件", bytes_complete: "文件已收齐，正在收尾", verifying: "正在核验结果", finalizing: "正在保存回收回执", finalized: "回收完成", retry_wait: "等待自动恢复", paused: "已暂停", conflict: "需要核对结果", credentials_required: "请恢复登录" };
  return <div className="member-transfer"><div><b>{title}</b><span>{progress.message || states[transferState] || "正在处理"}{completed != null && total != null ? ` · ${completed} / ${total} ${noun}` : ""}</span></div>{fraction != null && <progress aria-label={title} value={fraction} max="1" />}{transferState === "preparing" && progress.source_total_bytes > 0 && <small>源文件校验：{(Number(progress.source_checked_bytes || 0) / 1048576).toFixed(1)} / {(progress.source_total_bytes / 1048576).toFixed(1)} MiB</small>}</div>;
}

function MemberOperations({ online }) {
  const [operations, setOperations] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const refresh = usePageRefresh(async ({ signal, isCurrent }) => {
    try {
      const data = await api("/local/v1/operations", { signal });
      if (isCurrent()) { setOperations(data.operations || []); setError(""); }
    } catch (failure) { if (isCurrent()) setError(errorMessage(failure)); }
    finally { if (isCurrent()) setLoading(false); }
  }, { initial: true });
  const update = useCallback((operation) => setOperations((current) => {
    if (current.some((item) => item.operation_id === operation.operation_id)) return current.map((item) => item.operation_id === operation.operation_id ? operation : item);
    return [operation, ...current];
  }), []);
  return <main className="app-page member-page"><div className="page-title"><div><span>MEMBER / RUNS</span><h1>我的任务</h1><p>本机保存的提交记录可在重启客户端后继续上传、查询和回收。</p></div><div className="page-actions"><button className="button" onClick={refresh}><RefreshCw size={15} />刷新任务</button></div></div>
    {error && <div className="inline-error" role="alert">{error}</div>}
    {loading ? <p role="status">正在读取提交记录…</p> : !operations.length ? <section className="member-panel"><h2>还没有提交记录</h2><p>准备好项目任务包后即可提交。</p><Link className="button button-primary" to="/app/submit"><Upload size={16} />提交任务</Link></section> : operations.map((operation) => <OperationCard key={operation.operation_id} operation={operation} onChange={update} online={online} />)}
  </main>;
}

export function MemberContribution({ online, session }) {
  const [state, setState] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const mutation = useMutationGuard();
  const [pending, setPending] = useState([]);
  const pendingRef = useRef([]);
  const scopeRef = useRef(null);
  const loadedScope = useRef("");
  const [blocked, setBlocked] = useState(false);
  const [notDelivered, setNotDelivered] = useState({});
  const [notice, setNotice] = useState("");
  const [invite, setInvite] = useState("");
  const [workRoot, setWorkRoot] = useState("");
  const [cpus, setCpus] = useState(1);
  const [memory, setMemory] = useState(4096);
  const [memoryReserve, setMemoryReserve] = useState(1024);
  const [schedule, setSchedule] = useState({ days: [0, 1, 2, 3, 4, 5, 6], start: "00:00", end: "00:00" });
  const [scheduleEdited, setScheduleEdited] = useState(false);
  const [timezone, setTimezone] = useState(() => Intl.DateTimeFormat().resolvedOptions().timeZone);
  const [consent, setConsent] = useState(false);
  const preferencesHydrated = useRef(false);
  const checkpoints = (values) => {
    const saved = saveContributionCheckpoints(localStorage, scopeRef.current, values);
    pendingRef.current = saved; setPending(saved);
  };
  const acceptReceipt = (receipt, checkpoint) => {
    if (receipt.result) setState((previous) => !previous || receipt.result.revision >= previous.revision ? receipt.result : previous);
    if (!["completed", "failed"].includes(receipt.operation.status)) {
      setNotice("原请求结果尚未确认，编号已保留；不会重复配置机器或重发偏好。");
      return;
    }
    checkpoints(pendingRef.current.filter((item) => item.operation_id !== checkpoint.operation_id));
    if (receipt.operation.status === "failed") {
      setError(receipt.operation.error.message); setNotice("原请求已确认失败，未应用到中心；新修改需要你明确操作。"); return;
    }
    setNotice("原接入请求已核对，原结果已确认。");
  };
  const refresh = usePageRefresh(async ({ signal, isCurrent }) => {
    try {
      const value = await api("/local/v1/contribution", { signal });
      if (!isCurrent()) return;
      setState(value); setError("");
      if (!preferencesHydrated.current) {
        preferencesHydrated.current = true;
        if (value.preferences?.max_cpus != null) setCpus(value.preferences.max_cpus);
        if (value.preferences?.max_memory_mb != null) setMemory(value.preferences.max_memory_mb);
        if (value.preferences?.memory_reserve_mb != null) setMemoryReserve(value.preferences.memory_reserve_mb);
        if (value.preferences?.timezone) setTimezone(value.preferences.timezone);
        const windows = value.preferences?.weekly_windows;
        if (windows && Object.keys(windows).length) {
          const first = Object.values(windows).find((items) => items.length)?.[0];
          if (first) setSchedule({ days: Object.keys(windows).filter((day) => windows[day].length).map(Number), start: first.start, end: first.end });
        }
        setScheduleEdited(false);
      }
      if (value.work_root) setWorkRoot(value.work_root);
      const scope = contributionScope(session, value);
      const scopeKey = JSON.stringify(scope);
      if (loadedScope.current !== scopeKey) {
        loadedScope.current = scopeKey;
        scopeRef.current = scope;
        let saved;
        try { saved = loadContributionCheckpoints(localStorage, scope); }
        catch (failure) { setBlocked(true); throw failure; }
        for (const operation of value.pending_operations || []) {
          if (!saved.some((item) => item.operation_id === operation.operation_id)) saved.push({ ...scope,
            operation_id: operation.operation_id, kind: operation.kind, action: operation.kind,
            machine_id: operation.machine_id, expected_revision: operation.expected_revision });
        }
        try { checkpoints(saved); }
        catch (failure) { setBlocked(true); throw failure; }
        if (saved.length) await mutation.run(async () => {
          setBusy("recovery");
          try {
            for (const checkpoint of saved) {
              try {
                const receipt = await readContributionOriginal((path) => api(path, { signal }), checkpoint);
                if (isCurrent()) acceptReceipt(receipt, checkpoint);
              } catch (failure) {
                if (isCurrent()) {
                  setNotDelivered((current) => ({ ...current, [checkpoint.operation_id]: contributionNotFound(failure) }));
                  setError(errorMessage(failure));
                }
              }
            }
          } finally { if (isCurrent()) setBusy(""); }
        });
      }
    } catch (failure) { if (isCurrent()) setError(errorMessage(failure)); }
  }, { initial: true });
  const resourcePreferences = () => {
    if (scheduleEdited || !state?.preferences?.weekly_windows) {
      if (!schedule.days.length) throw new Error("请至少选择一个允许计算的星期");
    }
    return { max_cpus: Number(cpus), max_memory_mb: Number(memory), memory_reserve_mb: Number(memoryReserve), min_free_disk_mb: 10240, reserved_cpu_percent: 25, timezone, weekly_windows: !scheduleEdited && state?.preferences?.weekly_windows ? state.preferences.weekly_windows : Object.fromEntries(schedule.days.map((day) => [day, [{ start: schedule.start, end: schedule.end }]])) };
  };
  const editSchedule = (change) => { setScheduleEdited(true); setSchedule(change); };
  const perform = async (kind, payload, action) => {
    if (blocked || pendingRef.current.length && (action !== "pause" || pendingRef.current.some((item) => item.action === "pause"))) {
      setError("请先核对原接入请求；未知结果不能转为新的配置或偏好修改。"); return;
    }
    setBusy(kind); setError(""); setNotice("");
    try {
      const scope = contributionScope(session, state);
      scopeRef.current = scope;
      let machine = state.machine_id || "";
      if (kind === "setup") { try { machine = JSON.parse(payload.invite).machine_id || ""; } catch { /* server validates the private invite */ } }
      const checkpoint = { ...scope, kind, action, machine_id: machine, expected_revision: state.revision, operation_id: crypto.randomUUID() };
      checkpoints([...pendingRef.current, checkpoint]);
      try { acceptReceipt(await submitContribution(api, checkpoint, payload), checkpoint); }
      catch (failure) {
        setNotDelivered((current) => ({ ...current, [checkpoint.operation_id]: failure.notDelivered === true }));
        throw failure;
      }
    } catch (failure) { setError(errorMessage(failure)); }
    finally {
      if (kind === "setup") { setInvite(""); setConsent(false); }
      setBusy("");
    }
  };
  const recover = (checkpoint) => mutation.run(async () => {
    setBusy("recovery"); setError("");
    try { acceptReceipt(await readContributionOriginal(api, checkpoint), checkpoint); }
    catch (failure) {
      setNotDelivered((current) => ({ ...current, [checkpoint.operation_id]: contributionNotFound(failure) }));
      setError(errorMessage(failure));
    } finally { setBusy(""); }
  });
  const setup = (event) => mutation.run(async () => {
    event.preventDefault();
    if (!online) return;
    await perform("setup", { invite: invite.trim(), work_root: workRoot.trim(), accepted: consent, ...resourcePreferences() }, "setup");
  }, event);
  const preferences = (changes) => mutation.run(async () => {
    if (!online && changes.paused !== true) return;
    await perform("preferences", changes, changes.paused === true ? "pause" : changes.paused === false ? "resume" : "preferences");
  });
  const connected = Boolean(state?.machine_id || state?.configured);
  const paused = state?.preferences?.paused ?? state?.paused;
  const pendingPause = pending.some((item) => item.action === "pause");
  const saveResources = (event) => {
    event.preventDefault();
    if (!online) return;
    try { void preferences(resourcePreferences()); } catch (failure) { setError(failure.message); }
  };
  return <main className="app-page member-page"><div className="page-title"><div><span>MEMBER / COMPUTE</span><h1>贡献我的电脑</h1><p>按你的允许时间和资源预算接活。个人任务提交可以独立使用。</p></div></div>
    {error && <div className="inline-error" role="alert">{error}</div>}
    {notice && <p role="status">{notice}</p>}
    {pending.map((checkpoint) => <section className="member-panel" key={checkpoint.operation_id} data-contribution-operation={checkpoint.operation_id}><h2>原接入请求待核对</h2><p>原编号 <code>{checkpoint.operation_id}</code> 已保留。重载后只查询此请求，不会重新配置机器。</p><button className="button" disabled={Boolean(busy)} onClick={() => recover(checkpoint)}>核对原接入请求</button>{notDelivered[checkpoint.operation_id] && <button className="button" disabled={Boolean(busy)} onClick={() => checkpoints(pendingRef.current.filter((item) => item.operation_id !== checkpoint.operation_id))}>结束已核实未送达的请求</button>}</section>)}
    {state?.policy_sync_pending && <p className="member-notice" role="status">本机暂停已生效，中心策略尚未同步。恢复连接并确认中心支持原回执后，再明确保存偏好或恢复接活。</p>}
    {connected ? <section className="member-panel"><header><h2>{state.machine_id || "我的计算节点"}</h2><span className="member-badge">{paused ? "已暂停接活" : state.message || state.status || "已接入"}</span></header><p>COMSOL：{state.comsol_version || state.runtime?.comsol_version || "等待检测"} · 验收：{state.admission?.message || state.admission?.status || "等待异步验收"}</p><p>注销后停止启动新单元，正在计算的单元继续排空；锁屏继续计算。</p><form className="member-resource-form" onSubmit={saveResources}><ResourceInputs cpus={cpus} setCpus={setCpus} memory={memory} setMemory={setMemory} memoryReserve={memoryReserve} setMemoryReserve={setMemoryReserve} /><ScheduleInputs schedule={schedule} setSchedule={editSchedule} timezone={timezone} setTimezone={setTimezone} /><button className="button" disabled={Boolean(busy) || blocked || pending.length > 0 || !online}>保存资源预算与时间</button></form><div className="member-actions"><button className="button button-primary" disabled={Boolean(busy) || blocked || pendingPause || pending.length > 0 && paused || (!online && paused)} onClick={() => preferences({ paused: !paused })}>{paused ? <Play size={16} /> : <Pause size={16} />}{paused ? "恢复接活" : "暂停接活"}</button><button className="button" disabled={Boolean(busy)} onClick={refresh}><RefreshCw size={16} />刷新接入状态</button></div></section>
      : <form className="member-panel member-contribution-form" onSubmit={setup}><h2>使用私密机器邀请接入</h2><p>电脑需要已有 COMSOL 6.4。客户端会检测安装与许可，并在安装必要组件时请求 Windows 管理员确认。</p><label>私密 v2 机器邀请<textarea value={invite} onChange={(event) => setInvite(event.target.value)} required autoComplete="off" /></label><label>计算工作目录<input value={workRoot} readOnly /></label><p>首版使用专用账户的受管计算目录。</p><ResourceInputs cpus={cpus} setCpus={setCpus} memory={memory} setMemory={setMemory} memoryReserve={memoryReserve} setMemoryReserve={setMemoryReserve} /><ScheduleInputs schedule={schedule} setSchedule={editSchedule} timezone={timezone} setTimezone={setTimezone} /><p>至少保留 25% 调度线程预算和 10 GiB 磁盘空间供你使用。</p><label className="member-consent"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} required /><span>我同意在所设资源范围内贡献计算，并保留随时暂停的权利。</span></label><button className="button button-primary" disabled={Boolean(busy) || blocked || pending.length > 0 || !consent || !workRoot || !online}><Cpu size={16} />{busy === "setup" ? "正在配置接入" : "同意并接入计算"}</button></form>}
  </main>;
}

function ResourceInputs({ cpus, setCpus, memory, setMemory, memoryReserve, setMemoryReserve }) {
  return <div className="member-resource-fields"><label>最多调度 CPU 线程<input type="number" min="1" max="256" step="1" value={cpus} onChange={(event) => setCpus(event.target.value)} required /></label><label>内存预算（MiB）<input type="number" min="256" max="1048576" step="256" value={memory} onChange={(event) => setMemory(event.target.value)} required /></label><label>为本机保留内存（MiB）<input type="number" min="0" max="1048576" step="256" value={memoryReserve} onChange={(event) => setMemoryReserve(event.target.value)} required /></label></div>;
}

function ScheduleInputs({ schedule, setSchedule, timezone, setTimezone }) {
  const dayNames = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"];
  return <fieldset className="member-schedule"><legend>允许计算时间</legend><div className="member-weekdays">{dayNames.map((name, day) => <label key={day}><input type="checkbox" checked={schedule.days.includes(day)} onChange={(event) => setSchedule((current) => ({ ...current, days: event.target.checked ? [...current.days, day].sort() : current.days.filter((value) => value !== day) }))} />{name}</label>)}</div><div className="member-resource-fields"><label>每天开始时间<input type="time" value={schedule.start} onChange={(event) => setSchedule((current) => ({ ...current, start: event.target.value }))} required /></label><label>每天结束时间<input type="time" value={schedule.end} onChange={(event) => setSchedule((current) => ({ ...current, end: event.target.value }))} required /></label><label>时区<input value={timezone} onChange={(event) => setTimezone(event.target.value)} required /></label></div><p>开始和结束相同时表示全天；结束早于开始时表示跨午夜。</p></fieldset>;
}
