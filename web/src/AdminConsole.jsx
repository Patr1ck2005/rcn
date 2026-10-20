import { useEffect, useMemo, useRef, useState } from "react";
import { usePageRefresh } from "./usePageRefresh";
import { Bell, BookOpen, Boxes, Cpu, FlaskConical, Gauge, KeyRound, RefreshCw, Server, ShieldCheck, UserRoundCog } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";

import { api } from "./api";
import { PersonPolicyEditor } from "./PersonalAccess";
import { useMutationGuard } from "./useMutationGuard";
import { markTokenIssuance, pendingTokenIssuance } from "./tokenIssuance";
import MemberInvitations from "./MemberInvitations.jsx";
import { clearSolverApproval, loadSolverApproval, recoverSolverApproval, saveSolverApproval, solverApprovalCheckpoint, validateSolverApproval } from "./solverApprovalCheckpoint";
import { DataLoadState, initialRequestState, RefreshStatus, settleResourceRequests } from "./AsyncState";
import { RuntimeControlDialog } from "./ControlDialogs";
import { HelpLink } from "./HelpSystem";

const tabs = [
  ["users", "用户与 Token", UserRoundCog], ["projects", "项目授权", Boxes],
  ["profiles", "Profile 版本", Cpu], ["approvals", "Solver 审批", ShieldCheck],
  ["templates", "模板环境", FlaskConical],
  ["nodes", "节点与运行时", Server], ["capacity", "容量策略", Gauge],
  ["breakglass", "Break-glass", KeyRound],
];
const time = (value) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "-";
const splitCsv = (value) => value.split(",").map((item) => item.trim()).filter(Boolean);
const adminResources = {
  users: "/v1/users", projects: "/v1/projects", projectRegistrations: "/v1/project-registrations", profiles: "/v1/profiles",
  approvals: "/v1/solver-approvals", templateEnvironments: "/v1/admin/template-environments",
  breakglass: "/v1/admin/break-glass", onboarding: "/v1/admin/onboarding/profiles",
  preflights: "/v1/admin/onboarding/runs", enrollments: "/v1/admin/enrollments",
  settings: "/v1/settings/features", executionRuntime: "/v1/execution-runtime",
};
const adminResourceKeys = Object.keys(adminResources);
const tabResources = {
  users: ["users", "profiles"], projects: ["projects", "projectRegistrations", "users", "profiles"], profiles: ["profiles"],
  approvals: ["approvals", "executionRuntime", "profiles", "projects"], templates: ["templateEnvironments"],
  nodes: ["users", "onboarding", "preflights", "enrollments", "projects", "profiles"], capacity: ["settings", "profiles"],
  breakglass: ["breakglass"],
};
const tabLoadingLabels = {
  users: "正在加载用户与角色", projects: "正在加载项目授权", profiles: "正在加载 Profile 版本",
  approvals: "正在加载 Solver 审批", templates: "正在加载模板环境", nodes: "正在加载节点与运行时",
  capacity: "正在加载容量策略", breakglass: "正在加载应急配置",
};
const tabHelpTopics = {
  users: "adminUsers", projects: "adminProjects", profiles: "adminProfiles",
  approvals: "adminApprovals", templates: "adminTemplates", nodes: "adminNodes",
  capacity: "adminCapacity", breakglass: "adminBreakglass",
};
const tabHelpCopy = {
  users: ["用户与身份", "个人 Token、角色边界与可追溯的停用流程"],
  projects: ["项目授权", "所有权、成员、Profile 白名单与运行配额"],
  profiles: ["执行 Profile", "不可变执行合同、能力边界与资源基线"],
  approvals: ["Solver 审批", "模板、Study、solver 与正式 Runtime 的兼容绑定"],
  templates: ["模板证据", "基线哈希、已观察变化、输出合同与最近 Job"],
  nodes: ["节点与 Runtime", "准入、preflight、候选晋升与可回滚发布"],
  capacity: ["容量与资源自治", "压力阈值、遥测质量、资源边界与证据调节"],
  breakglass: ["应急控制", "强身份、主机级终止、审计与恢复责任"],
};

const resourcePolicyFor = (profile, stored) => stored || ({
  schema_version: 1, profile_id: profile.profile_id, revision: 1,
  baseline: { ...profile.default_resources },
  minimum: { cpus: 1, memory_mb: 256, disk_mb: 0, gpus: 0 },
  maximum: { cpus: 64, memory_mb: 262144, disk_mb: 1048576, gpus: 8 },
  minimum_success_samples: 20, downward_step_percent: 10,
  memory_percentile: 99, memory_margin_percent: 25, memory_margin_floor_mb: 2048,
  disk_percentile: 99, disk_margin_percent: 25, disk_margin_floor_mb: 1024,
  automatic_adjustment: true,
});

function ResourcePolicyEditor({ profiles, policies, onSaved, setError, setNotice }) {
  const mutation = useMutationGuard();
  const [profileId, setProfileId] = useState("");
  const [draft, setDraft] = useState(null);
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const selected = profiles.find((item) => item.profile_id === profileId) || profiles[0];
  useEffect(() => {
    if (!selected) return;
    if (!profileId) setProfileId(selected.profile_id);
    setDraft(resourcePolicyFor(selected, policies?.[selected.profile_id]));
    setPreview(null);
  }, [profileId, selected?.profile_id, policies]);
  if (!selected || !draft) return null;
  const updateResource = (group, key, value) => setDraft({ ...draft, [group]: { ...draft[group], [key]: Number(value) } });
  const updateNumber = (key, value) => setDraft({ ...draft, [key]: Number(value) });
  const makePreview = () => mutation.run(async () => {
    setBusy(true); setError("");
    try { setPreview(await api(`/v1/admin/resource-policies/${selected.profile_id}/preview`, { method: "POST", body: JSON.stringify({ ...draft, profile_id: selected.profile_id }) })); }
    catch (caught) { setError(caught.message); } finally { setBusy(false); }
  });
  const confirm = () => mutation.run(async () => {
    setBusy(true); setError("");
    try {
      await api(`/v1/admin/resource-policies/${selected.profile_id}/confirm`, { method: "POST", body: JSON.stringify({ policy: { ...draft, profile_id: selected.profile_id }, expected_revision: preview.expected_revision, confirmation_hash: preview.confirmation_hash }) });
      setNotice("资源策略已保存；运行中 Attempt 不变，未启动 Unit 使用新 revision"); setPreview(null); await onSaved();
    } catch (caught) { setError(caught.message); } finally { setBusy(false); }
  });
  const fields = [
    ["cpus", "CPU", "Network 解析的每个 Unit CPU 基线或边界；运行中 Attempt 不会被修改。"],
    ["memory_mb", "内存 MiB", "Network 用于资源门槛的 MiB 数值；自动调整只在成功样本达到门槛后生效。"],
    ["disk_mb", "磁盘 MiB", "Network 为 Unit 预留的工作与输出磁盘空间，不代表整台机器剩余磁盘。"],
    ["gpus", "GPU", "GPU 数量是静态能力约束，不依据瞬时低利用率自动下调。"],
  ];
  const groupLabels = { baseline: "基线", minimum: "最小", maximum: "最大" };
  const policyHints = {
    minimum_success_samples: "达到该数量的同 Profile 成功样本后，Network 才允许渐进调整内存与磁盘。",
    downward_step_percent: "每轮自动下调的上限；上调不受此下调上限限制。",
    memory_percentile: "内存峰值取样的百分位，再叠加百分比余量与绝对下限。",
    memory_margin_percent: "内存 P99 之外的相对安全余量。",
    memory_margin_floor_mb: "内存安全余量的绝对下限，防止小样本得到过小余量。",
    disk_percentile: "磁盘峰值取样的百分位，再叠加磁盘安全余量。",
    disk_margin_percent: "磁盘 P99 之外的相对安全余量。",
    disk_margin_floor_mb: "磁盘安全余量的绝对下限。",
  };
  return <div className="resource-policy-editor"><h3>Network 资源解析策略</h3><label className="policy-profile-selector">执行 Profile<select value={selected.profile_id} onChange={(event) => setProfileId(event.target.value)}>{profiles.map((profile) => <option key={profile.profile_id} value={profile.profile_id}>{profile.profile_id}</option>)}</select></label>
    <section className="policy-group" aria-labelledby="policy-boundaries-title"><header><h4 id="policy-boundaries-title">资源边界</h4><p>基线用于初始解析，最小值与最大值约束所有自动调整。</p></header><div className="policy-resource-groups">{["baseline", "minimum", "maximum"].map((group) => <fieldset key={group}><legend>{groupLabels[group]}</legend><div>{fields.map(([key, fieldLabel, hint]) => <label key={`${group}-${key}`} title={hint}>{fieldLabel}<input aria-label={`${groupLabels[group]} ${fieldLabel}`} type="number" min={key === "memory_mb" ? 256 : 0} value={draft[group][key]} onChange={(event) => updateResource(group, key, event.target.value)} /></label>)}</div></fieldset>)}</div></section>
    <section className="policy-group" aria-labelledby="policy-evidence-title"><header><h4 id="policy-evidence-title">自适应证据与安全余量</h4><p>成功样本达到门槛后，按稳健分位数和安全余量渐进调整。</p></header><div className="policy-evidence-grid"><label title={policyHints.minimum_success_samples}>最少成功样本<input aria-label="最少成功样本" type="number" min="1" value={draft.minimum_success_samples} onChange={(event) => updateNumber("minimum_success_samples", event.target.value)} /></label><label title={policyHints.downward_step_percent}>单轮最大下调 %<input aria-label="单轮最大下调百分比" type="number" min="0.1" max="10" step="0.1" value={draft.downward_step_percent} onChange={(event) => updateNumber("downward_step_percent", event.target.value)} /></label><label title={policyHints.memory_percentile}>内存百分位<input aria-label="内存百分位" type="number" min="50" max="100" value={draft.memory_percentile} onChange={(event) => updateNumber("memory_percentile", event.target.value)} /></label><label title={policyHints.memory_margin_percent}>内存余量 %<input aria-label="内存余量百分比" type="number" min="0" value={draft.memory_margin_percent} onChange={(event) => updateNumber("memory_margin_percent", event.target.value)} /></label><label title={policyHints.memory_margin_floor_mb}>内存余量下限 MiB<input aria-label="内存余量下限 MiB" type="number" min="0" value={draft.memory_margin_floor_mb} onChange={(event) => updateNumber("memory_margin_floor_mb", event.target.value)} /></label><label title={policyHints.disk_percentile}>磁盘百分位<input aria-label="磁盘百分位" type="number" min="50" max="100" value={draft.disk_percentile} onChange={(event) => updateNumber("disk_percentile", event.target.value)} /></label><label title={policyHints.disk_margin_percent}>磁盘余量 %<input aria-label="磁盘余量百分比" type="number" min="0" value={draft.disk_margin_percent} onChange={(event) => updateNumber("disk_margin_percent", event.target.value)} /></label><label title={policyHints.disk_margin_floor_mb}>磁盘余量下限 MiB<input aria-label="磁盘余量下限 MiB" type="number" min="0" value={draft.disk_margin_floor_mb} onChange={(event) => updateNumber("disk_margin_floor_mb", event.target.value)} /></label></div></section>
    <div className="policy-actions"><label title="关闭后保留当前策略，但 Network 不会根据新成功样本自动调整。"><input type="checkbox" checked={draft.automatic_adjustment} onChange={(event) => setDraft({ ...draft, automatic_adjustment: event.target.checked })} />达到样本门槛后允许 Network 渐进调整内存与磁盘</label><button className="button button-primary" title="先生成当前 revision 的候选值，确认后才会保存" disabled={busy} onClick={makePreview}>预览资源策略变更</button></div>
    {preview && <div className="control-preview"><p>revision {preview.expected_revision} → {preview.candidate.revision}。运行中 Attempt 不变；未启动 Unit 使用新策略。</p><div><button className="button" onClick={() => setPreview(null)}>返回修改</button><button className="button button-primary" disabled={busy} onClick={confirm}>确认保存</button></div></div>}
  </div>;
}

function ProjectRegistrationReview({ registrations, onReview }) {
  const pending = registrations.filter((item) => item.status === "requested");
  return <section className="detail-section registration-review"><header><div><h2>待确认项目登记</h2><span>确认 owner、固定 Profile、默认配额与 priority ceiling 后启用</span></div><span>{pending.length} 项</span></header><div className="registration-review-list">{pending.map((item) => <article key={item.registration_id}><div><b>{item.display_name}</b><small>{item.project_id} · owner {item.requested_by}</small><p>{item.purpose}</p><code>{item.requested_profiles.join(" · ")}</code></div><div><button className="button small" onClick={() => onReview(item, false)}>拒绝</button><button className="button button-primary small" onClick={() => onReview(item, true)}>确认项目</button></div></article>)}{!pending.length && <p className="empty-copy">当前没有待确认的项目登记。</p>}</div></section>;
}

function ProjectPriorityControls({ projects, onSave }) {
  const [drafts, setDrafts] = useState({});
  return <section className="detail-section project-priority-controls"><header><div><h2>项目 Priority ceiling</h2><span>提交者不能超过项目上限；等待老化仍防止低优先级无限饥饿</span></div></header><div>{projects.map((project) => <label key={project.project_id}><span><b>{project.project_id}</b><small>{project.max_running_units} running / {project.max_queued_units} queued</small></span><input type="number" min="-100" max="100" value={drafts[project.project_id] ?? project.priority_ceiling ?? 0} onChange={(event) => setDrafts((current) => ({ ...current, [project.project_id]: Number(event.target.value) }))} /><button className="button small" onClick={() => onSave(project, drafts[project.project_id] ?? project.priority_ceiling ?? 0)}>保存上限</button></label>)}</div></section>;
}

export default function AdminConsole({ overview = {}, actorId = "", onGlobalRefresh }) {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") || "users";
  const [data, setData] = useState({ users: [], projects: [], projectRegistrations: [], profiles: [], approvals: [], templateEnvironments: [], breakglass: {}, onboarding: [], preflights: [], enrollments: [], settings: {}, executionRuntime: {} });
  const [requests, setRequests] = useState(() => initialRequestState(adminResourceKeys));
  const [error, setError] = useState("");
  const [selectedUser, setSelectedUser] = useState(null);
  const [tokens, setTokens] = useState([]);
  const [tokensRequest, setTokensRequest] = useState({ status: "idle", error: "" });
  const [issuedToken, setIssuedToken] = useState(null);
  const [pendingTokens, setPendingTokens] = useState(() => {
    try { return pendingTokenIssuance(sessionStorage, actorId); }
    catch { return { unreadable: true }; }
  });
  const [pin, setPin] = useState("");
  const [notice, setNotice] = useState("");
  const [mutating, setMutating] = useState(false);
  const mutation = useMutationGuard();
  const [userDraft, setUserDraft] = useState({ user_id: "", display_name: "", roles: ["member"] });
  const [projectDraft, setProjectDraft] = useState({ project_id: "", owner_user_id: "", authorized_user_ids: "", allowed_profiles: "", trusted_machine_labels: "group-trusted", max_queued_units: 2000, max_running_units: 4, priority_ceiling: 0, approved: true, status: "active" });
  const [profileDraft, setProfileDraft] = useState({ profile_id: "", version: "1.0.0", executor_kind: "project_worker", platforms: "windows", required_capabilities: "python-project-worker", output_schema: "", cpus: 1, memory_mb: 1024, disk_mb: 1024, gpus: 0 });
  const [approvalDraft, setApprovalDraft] = useState({ project_id: "", execution_profile_id: "workbench-comsol-study-v1", comsol_version: "6.4", template_sha256: "", template_role: "", allowed_study_kinds: "eigenfrequency, frequency_domain", template_hash_policy: "warn_on_change", mesh_mode: "auto_size", mesh_tag: "mesh1", mesh_size: "fine" });
  const [runtimeControl, setRuntimeControl] = useState(null);
  const [approvalPending, setApprovalPending] = useState(null);
  const [approvalReady, setApprovalReady] = useState(false);
  const currentActor = useRef(actorId); currentActor.current = actorId;
  const approvalAlive = useRef(true);
  useEffect(() => { approvalAlive.current = true; return () => { approvalAlive.current = false; }; }, []);
  const [pressureDraft, setPressureDraft] = useState({
    external_cpu_threshold_percent: 10,
    external_gpu_threshold_percent: 40,
    memory_mode: "resource_gate_only",
    external_memory_threshold_mb: 4096,
    available_memory_floor_mb: 8192,
    enter_after_seconds: 30,
    clear_after_seconds: 120,
    pressured_dispatch_cap: 1,
    telemetry_stale_cap: 1,
    max_override_minutes: 30,
  });
  const [telemetryDraft, setTelemetryDraft] = useState({
    sample_interval_s: 1, cpu_sample_window_s: 60, peak_window_s: 300,
    sample_timeout_s: 8, stale_after_s: 45,
    external_process_names: ["comsol", "mphserver", "comsol server"],
  });
  const generations = useRef({});
  const load = async (resourceKeys = tabResources[tab], preserveDrafts = true, context = null) => {
    const keys = [...new Set(resourceKeys)];
    const generation = Object.fromEntries(keys.map((key) => [key, generations.current[key] = (generations.current[key] || 0) + 1]));
    const currentRequest = (key) => (!context || context.isCurrent()) && generation[key] === generations.current[key];
    setRequests((current) => Object.fromEntries(Object.entries(current).map(([key, state]) => [
      key, keys.includes(key) ? { ...state, status: state.updatedAt ? "refreshing" : "loading", error: "" } : state,
    ])));
    return settleResourceRequests(keys, (key) => api(adminResources[key], { signal: context?.signal }), (key, value) => {
        if (!currentRequest(key)) return;
        setData((current) => ({ ...current, [key]: value }));
        if (key === "settings" && (!preserveDrafts || !requests.settings?.updatedAt)) {
          setPressureDraft(value.pressure_policy);
          setTelemetryDraft(value.telemetry_policy || telemetryDraft);
        }
        setRequests((current) => ({ ...current, [key]: { status: "ready", error: "", updatedAt: new Date().toISOString() } }));
      }, (key, caught) => {
        if (!currentRequest(key)) return;
        setRequests((current) => ({ ...current, [key]: { ...current[key], status: "error", error: caught.message } }));
      });
  };
  const refreshPage = usePageRefresh((context) => load(tabResources[tab], true, context), { key: tab, initial: true, resources: tabResources[tab] });
  useEffect(() => {
    if (!selectedUser) { setTokens([]); setTokensRequest({ status: "idle", error: "" }); return undefined; }
    let active = true;
    setTokens([]); setTokensRequest({ status: "loading", error: "" });
    api(`/v1/users/${selectedUser}/tokens`).then((items) => {
      if (active) { setTokens(items); setTokensRequest({ status: "ready", error: "" }); }
    }).catch((caught) => {
      if (active) setTokensRequest({ status: "error", error: caught.message });
    });
    return () => { active = false; };
  }, [selectedUser]);
  const perform = (action, success) => mutation.run(async () => { setMutating(true); try { setError(""); await action(); setNotice(success); await load(tabResources[tab]); await onGlobalRefresh?.(); } catch (caught) { setError(caught.message); } finally { setMutating(false); } });
  const updateUser = async (user, active) => perform(() => api(`/v1/users/${user.user_id}`, { method: "PUT", body: JSON.stringify({ ...user, active }) }), active ? "用户已恢复" : "用户已停用");
  const saveUser = async () => perform(async () => { await api(`/v1/users/${userDraft.user_id}`, { method: "PUT", body: JSON.stringify({ ...userDraft, active: true }) }); setUserDraft({ user_id: "", display_name: "", roles: ["member"] }); }, "用户与角色已保存");
  const inspectTokens = (userId) => { setSelectedUser(null); queueMicrotask(() => setSelectedUser(userId)); };
  const issueToken = (userId, agent = false) => mutation.run(async () => {
    let marked = false;
    setMutating(true); setError("");
    try {
      const pending = pendingTokenIssuance(sessionStorage, actorId);
      if (pending[userId]) { setPendingTokens(pending); setError("原 Token 签发结果尚未确认，请先核对已有 Token；不会重复签发。"); return; }
      const checkpoint = markTokenIssuance(sessionStorage, actorId, userId, true, agent);
      setPendingTokens(checkpoint); marked = true;
      const issued = await api(`/v1/users/${encodeURIComponent(userId)}/tokens`, { method: "POST", headers: { "X-RCN-Request-ID": checkpoint[userId].request_id }, ...(checkpoint[userId].agent ? { body: JSON.stringify({ agent: true }) } : {}) });
      if (!issued?.token || issued.user_id !== userId) throw new Error("未收到与目标用户匹配的 Token 交付回执");
      setIssuedToken({ ...issued, agent: Boolean(checkpoint[userId].agent) });
      setPendingTokens(markTokenIssuance(sessionStorage, actorId, userId, false));
      inspectTokens(userId);
    } catch (caught) {
      if (marked && caught.status && caught.status < 500 && caught.reasonCode !== "token_issuance_requires_reconciliation") {
        try { setPendingTokens(markTokenIssuance(sessionStorage, actorId, userId, false)); } catch { /* Keep the durable checkpoint. */ }
      }
      setError(`${caught.message}${marked && (!caught.status || caught.status >= 500) ? "。签发结果未知，可能已经生成 Token；原检查点已保留，先核对并撤销无法交付的 Token，不自动重签。" : ""}`);
    } finally { setMutating(false); }
  });
  const revokeToken = (userId, tokenId) => mutation.run(async () => {
    setMutating(true); setError("");
    try { await api(`/v1/users/${encodeURIComponent(userId)}/tokens/${encodeURIComponent(tokenId)}`, { method: "DELETE" }); setTokens(await api(`/v1/users/${encodeURIComponent(userId)}/tokens`)); }
    catch (caught) { setError(`撤销结果待核对：${caught.message}。可核对并重试同一个 Token，不会签发新凭据。`); }
    finally { setMutating(false); }
  });
  const setProjectActive = async (project, active) => perform(() => api(`/v1/admin/projects/${project.project_id}/freeze`, {
    method: "POST",
    body: JSON.stringify({
      frozen: !active,
      reason: active ? "管理员恢复项目" : "管理员冻结项目",
    }),
  }), active ? "项目已恢复" : "项目已冻结");
  const saveProject = async () => perform(async () => { await api(`/v1/projects/${projectDraft.project_id}`, { method: "PUT", body: JSON.stringify({ ...projectDraft, authorized_user_ids: splitCsv(projectDraft.authorized_user_ids), allowed_profiles: splitCsv(projectDraft.allowed_profiles), trusted_machine_labels: splitCsv(projectDraft.trusted_machine_labels) }) }); }, "项目授权与配额已保存");
  const reviewProject = async (registration, approve) => perform(() => api(`/v1/admin/project-registrations/${registration.registration_id}/review`, { method: "POST", body: JSON.stringify({ approve, allowed_profiles: approve ? [...registration.requested_profiles] : [], priority_ceiling: 0, reason: approve ? "管理员完成首次确认" : "管理员拒绝登记申请" }) }), approve ? "项目首次确认完成" : "项目登记已拒绝");
  const savePriorityCeiling = async (project, priorityCeiling) => perform(() => api(`/v1/projects/${project.project_id}`, { method: "PUT", body: JSON.stringify({ ...project, priority_ceiling: Number(priorityCeiling) }) }), "项目 Priority ceiling 已保存");
  const createProfile = async () => perform(async () => { await api("/v1/profiles", { method: "POST", body: JSON.stringify({ profile_id: profileDraft.profile_id, version: profileDraft.version, executor_kind: profileDraft.executor_kind, platforms: splitCsv(profileDraft.platforms), required_capabilities: splitCsv(profileDraft.required_capabilities), output_schema: profileDraft.output_schema, allow_arbitrary_command: false, default_resources: { cpus: Number(profileDraft.cpus), memory_mb: Number(profileDraft.memory_mb), disk_mb: Number(profileDraft.disk_mb), gpus: Number(profileDraft.gpus) } }) }); }, "不可变 Profile 版本已创建");
  const finishApproval = async (value, result) => {
    if (!approvalAlive.current || currentActor.current !== value.actor_id) return;
    if (result.approvals) {
      setData((current) => ({ ...current, approvals: result.approvals }));
      setRequests((current) => ({ ...current, approvals: { status: "ready", error: "", updatedAt: new Date().toISOString() } }));
    } else await load(["approvals"]);
    if (!approvalAlive.current || currentActor.current !== value.actor_id) return;
    clearSolverApproval(sessionStorage, value); setApprovalPending(null);
    setNotice(`原 Solver 审批 ${result.approval.approval_id} 已核对${result.approval.active === false ? "（已撤销，不会重新激活）" : ""}。`);
  };
  const recoverApproval = (value = approvalPending) => mutation.run(async () => {
    if (!value || currentActor.current !== value.actor_id) return;
    setMutating(true); setError("");
    try { await finishApproval(value, await recoverSolverApproval(api, value)); }
    catch (caught) { if (currentActor.current === value.actor_id) setError(`原审批结果待核对：${caught.message}。保留原请求，不自动重复签发。`); }
    finally { if (currentActor.current === value.actor_id) setMutating(false); }
  });
  useEffect(() => {
    setApprovalReady(false); setApprovalPending(null);
    if (!actorId) return;
    try {
      const value = loadSolverApproval(sessionStorage, actorId); setApprovalReady(true); setApprovalPending(value);
      if (value) { if (value.draft) setApprovalDraft(value.draft); void recoverApproval(value); }
    } catch (caught) { setError(caught.message); }
  }, [actorId]);
  const issueApproval = () => mutation.run(async () => {
    if (!approvalReady || !actorId) return;
    setMutating(true); setError("");
    let value = approvalPending;
    try {
      if (!value) {
        const generic = approvalDraft.execution_profile_id === "workbench-comsol-study-v1";
        const payload = { project_id: approvalDraft.project_id, execution_profile_id: approvalDraft.execution_profile_id, comsol_version: approvalDraft.comsol_version, template_sha256: approvalDraft.template_sha256, approved_by: actorId, solver_variants: ["mumps", "cudss"], mesh_policy: { mode: approvalDraft.mesh_mode, mesh_tag: approvalDraft.mesh_tag, ...(approvalDraft.mesh_mode === "auto_size" ? { size: approvalDraft.mesh_size } : {}) }, ...(generic ? { template_role: approvalDraft.template_role, allowed_study_kinds: splitCsv(approvalDraft.allowed_study_kinds), template_hash_policy: approvalDraft.template_hash_policy, runtime_version: data.executionRuntime.runtime_version } : {}) };
        value = saveSolverApproval(sessionStorage, solverApprovalCheckpoint(actorId, payload, approvalDraft)); setApprovalPending(value);
      }
      if (value.actor_id !== actorId) throw new Error("审批检查点属于其他身份。");
      const approval = validateSolverApproval(await api("/v1/solver-approvals", { method: "POST", headers: { "X-RCN-Request-ID": value.request_id }, body: JSON.stringify(value.payload) }), value);
      await finishApproval(value, { approval });
    } catch (caught) {
      if (value) {
        try { await finishApproval(value, await recoverSolverApproval(api, value)); }
        catch (recoveryError) {
          if (approvalAlive.current && currentActor.current === value.actor_id) {
            if ([400, 404, 409, 410, 422].includes(caught.status) && recoveryError.status === 404) {
              const rejected = { ...value, rejected: true }; saveSolverApproval(sessionStorage, rejected); setApprovalPending(rejected);
              setError(`原审批请求已明确被拒绝：${caught.message}。可核对后结束原请求，再修改审批内容。`);
            } else setError(`审批结果待核对：${caught.message}。原请求已保留；核对或显式重试仍使用同一请求。`);
          }
        }
      } else setError(caught.message);
    } finally { if (!value || currentActor.current === value.actor_id) setMutating(false); }
  });
  const revokeApproval = async (id) => perform(() => api(`/v1/solver-approvals/${id}`, { method: "DELETE" }), "Solver 审批已撤销");
  const runPreflight = async (machineId) => perform(() => api(`/v1/admin/onboarding/${machineId}/preflight`, { method: "POST" }), `${machineId} preflight 已完成`);
  const rotatePin = () => mutation.run(async () => { setMutating(true); try { await api("/v1/admin/break-glass/pin", { method: "PUT", body: JSON.stringify({ pin }) }); await load(tabResources.breakglass); } catch (caught) { setError(caught.message); } finally { setPin(""); setMutating(false); } });
  const savePressurePolicy = async () => perform(
    () => api("/v1/settings/features", {
      method: "PUT",
      body: JSON.stringify({ ...data.settings, pressure_policy: pressureDraft, telemetry_policy: telemetryDraft }),
    }),
    "容量与压力策略已保存；后续真实遥测将按新策略判定",
  );
  const runtimeGroups = useMemo(() => Object.entries(overview.execution_configs || {}).map(([machineId, config]) => ({ machineId, config, machine: overview.machines?.find((item) => item.machine_id === machineId) })), [overview]);
  const activeResourceKeys = tabResources[tab] || [];
  const activeRequests = activeResourceKeys.map((key) => requests[key]);
  const initialLoading = activeRequests.some((request) => request?.status === "loading");
  const refreshing = activeRequests.some((request) => request?.status === "refreshing");
  const hasCachedTab = activeRequests.every((request) => request?.updatedAt);
  const loadError = activeRequests.find((request) => request?.status === "error")?.error || "";
  const refreshTab = refreshPage;
  return <main className="app-page" aria-busy={initialLoading || refreshing || mutating}><div className="page-title"><div><span>ADMIN / GOVERNANCE</span><h1>管理员面板</h1><p>身份、项目、不可变执行契约、审批、节点准入和应急控制</p></div><div className="page-actions"><RefreshStatus visible={refreshing || mutating} label={mutating ? "正在保存变更" : "正在更新"} /><button className="button" disabled={initialLoading || refreshing || mutating} onClick={refreshTab}><RefreshCw size={16} />刷新</button></div></div>{error && <div className="inline-error">{error}</div>}{notice && <div className="inline-success">{notice}</div>}
    <nav className="detail-tabs admin-tabs">{tabs.map(([value, text, Icon]) => <button key={value} className={tab === value ? "active" : ""} onClick={() => { setNotice(""); setParams({ tab: value }); }}><Icon size={15} />{text}</button>)}</nav>
    <section className="admin-guide" aria-label="管理员工作区说明"><BookOpen size={17} /><div><b>管理员工作区</b><span>配置按职责分区；变更保留审计，运行时、节点与应急操作遵循预览、确认和恢复边界。</span></div><HelpLink topic="adminControl">面板总览</HelpLink></section>
    <section className="admin-tab-guide" aria-label={`${tabHelpCopy[tab][0]}说明`}><div><span>CURRENT SECTION</span><b>{tabHelpCopy[tab][0]}</b><small>{tabHelpCopy[tab][1]}</small></div><HelpLink topic={tabHelpTopics[tab]}>本页说明</HelpLink></section>
    <fieldset disabled={mutating} style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
    {tab === "users" && Object.keys(pendingTokens).length > 0 && <section className="detail-section" aria-label="待核对的 Token 签发"><h2>Token 签发结果待核对</h2><p>请求可能已被接受，明文响应无法重新读取。先查看并撤销无法交付的 Token；本页和重新加载页面都不会自动重签。原请求是否已送达，需要管理员核对服务端审计后处理检查点。</p>{Object.entries(pendingTokens).filter(([id]) => id !== "unreadable").map(([id, marker]) => <p key={id}><b>{id}</b> · {time(marker.started_at)} <button className="button small" onClick={() => inspectTokens(id)}>核对现有 Token</button></p>)}</section>}
    {tab === "users" && !initialLoading && <PersonPolicyEditor users={data.users} profiles={data.profiles} />}
    {tab === "projects" && !initialLoading && (!loadError || hasCachedTab) && <ProjectRegistrationReview registrations={data.projectRegistrations} onReview={reviewProject} />}
    {tab === "projects" && !initialLoading && (!loadError || hasCachedTab) && <ProjectPriorityControls projects={data.projects} onSave={savePriorityCeiling} />}
    {tab === "nodes" && <MemberInvitations key={actorId} actorId={actorId} users={data.users} enrollments={data.enrollments} projects={data.projects} profiles={data.profiles} admissionReady={[requests.projects, requests.profiles].every(request => ["ready", "refreshing"].includes(request?.status))} ready={[requests.users, requests.enrollments].every(request => ["ready", "refreshing"].includes(request?.status))} onRefresh={() => load(["users", "enrollments", "projects", "profiles"], true)} />}
    {loadError && hasCachedTab && <p className="inline-error">刷新失败：{loadError}。保留上次成功内容。</p>}
    {(initialLoading || (loadError && !hasCachedTab)) ? <DataLoadState label={tabLoadingLabels[tab]} error={loadError} onRetry={refreshTab} /> : <>
    {tab === "users" && <section className="detail-section"><header><div><h2>用户与角色</h2><span>停用保留历史 provenance</span></div></header><p>Agent Token 只用于该用户本人获准的计算，可单独撤销；不具管理员或机器所有者管理权限。</p><div className="admin-form user-form"><label>用户 ID<input value={userDraft.user_id} onChange={(event) => setUserDraft({ ...userDraft, user_id: event.target.value })} /></label><label>显示名称<input value={userDraft.display_name} onChange={(event) => setUserDraft({ ...userDraft, display_name: event.target.value })} /></label><fieldset><legend>角色</legend>{["member", "machine_owner", "admin"].map((role) => <label key={role}><input type="checkbox" checked={userDraft.roles.includes(role)} onChange={(event) => setUserDraft({ ...userDraft, roles: event.target.checked ? [...new Set([...userDraft.roles, role])] : userDraft.roles.filter((item) => item !== role) })} />{role}</label>)}</fieldset><button className="button button-primary" disabled={!userDraft.user_id || !userDraft.display_name || !userDraft.roles.length} onClick={saveUser}>保存用户</button></div><div className="admin-table"><div className="admin-table-head"><span>用户</span><span>角色</span><span>状态</span><span>Token</span><span>操作</span></div>{data.users.map((user) => <div key={user.user_id}><b>{user.display_name || user.user_id}<small>{user.user_id}</small></b><span>{[...user.roles].join(" · ")}</span><span>{user.active ? "活动" : "停用"}</span><button className="text-button" onClick={() => setSelectedUser(user.user_id)}>查看 {selectedUser === user.user_id && tokensRequest.status === "ready" ? tokens.length : ""}</button><div style={{ flexWrap: "wrap" }}><button className="button small" onClick={() => { setUserDraft({ user_id: user.user_id, display_name: user.display_name, roles: [...user.roles] }); }}>编辑</button><button className="button small" disabled={Boolean(pendingTokens.unreadable || pendingTokens[user.user_id])} onClick={() => issueToken(user.user_id)}>签发</button><button className="button small" disabled={Boolean(pendingTokens.unreadable || pendingTokens[user.user_id])} onClick={() => issueToken(user.user_id, true)}>签发 Agent Token</button><button className="button small" onClick={() => updateUser(user, !user.active)}>{user.active ? "停用" : "恢复"}</button></div></div>)}{!data.users.length && <div className="admin-empty-row">尚未创建用户。</div>}</div>{selectedUser && <div className="token-panel"><header><h3>{selectedUser} / tokens</h3></header>{issuedToken?.user_id === selectedUser && <div className="secret-once"><KeyRound size={17} /><div><b>{issuedToken.agent ? "Agent Token · 仅显示一次" : "仅显示一次"}</b><code>{issuedToken.token}</code></div></div>}{tokensRequest.status === "loading" || tokensRequest.status === "error" ? <DataLoadState compact label="正在加载个人 Token" error={tokensRequest.error} onRetry={() => { setSelectedUser(null); queueMicrotask(() => setSelectedUser(selectedUser)); }} /> : <div className="deep-list">{tokens.map((item) => <div key={item.token_id}><KeyRound size={15} /><span><b>{item.token_id}</b><small>{item.active ? "active" : "revoked"} · 范围 {(item.scopes || ["api"]).join(" · ")} · {time(item.created_at)}</small></span>{item.active && <button className="button small" onClick={() => revokeToken(selectedUser, item.token_id)}>撤销</button>}</div>)}{!tokens.length && <p className="empty-copy">该用户尚无 Token。</p>}</div>}</div>}</section>}
    {tab === "projects" && <section className="detail-section"><header><div><h2>项目授权与配额</h2><span>项目只冻结，不硬删除；Agent 必须列入授权用户</span></div></header><div className="admin-form project-form"><label>项目 ID<input value={projectDraft.project_id} onChange={(event) => setProjectDraft({ ...projectDraft, project_id: event.target.value })} /></label><label>所有者<input value={projectDraft.owner_user_id} onChange={(event) => setProjectDraft({ ...projectDraft, owner_user_id: event.target.value })} /></label><label>授权 Agent / 成员<input value={projectDraft.authorized_user_ids} onChange={(event) => setProjectDraft({ ...projectDraft, authorized_user_ids: event.target.value })} placeholder="用户 ID，逗号分隔" /></label><label>允许 Profile<input value={projectDraft.allowed_profiles} onChange={(event) => setProjectDraft({ ...projectDraft, allowed_profiles: event.target.value })} placeholder="逗号分隔" /></label><label>可信机器标签<input value={projectDraft.trusted_machine_labels} onChange={(event) => setProjectDraft({ ...projectDraft, trusted_machine_labels: event.target.value })} /></label><label>排队上限<input type="number" min="1" value={projectDraft.max_queued_units} onChange={(event) => setProjectDraft({ ...projectDraft, max_queued_units: Number(event.target.value) })} /></label><label>运行上限<input type="number" min="1" value={projectDraft.max_running_units} onChange={(event) => setProjectDraft({ ...projectDraft, max_running_units: Number(event.target.value) })} /></label><button className="button button-primary" disabled={!projectDraft.project_id || !projectDraft.owner_user_id} onClick={saveProject}>保存项目</button></div><div className="admin-table projects-table"><div className="admin-table-head"><span>项目</span><span>所有者</span><span>授权成员</span><span>运行配额</span><span>允许 Profile</span><span>状态</span></div>{data.projects.map((project) => { const active = project.status === "active"; return <div key={project.project_id}><b>{project.project_id}</b><span>{project.owner_user_id}</span><span>{project.authorized_user_ids?.join(" · ") || "仅所有者"}</span><span>{project.max_running_units} / {project.max_queued_units}</span><span>{project.allowed_profiles?.join(" · ") || "-"}</span><div><button className="button small" onClick={() => setProjectDraft({ ...project, authorized_user_ids: (project.authorized_user_ids || []).join(", "), allowed_profiles: project.allowed_profiles.join(", "), trusted_machine_labels: project.trusted_machine_labels.join(", ") })}>编辑</button><button className="button small" onClick={() => setProjectActive(project, !active)}>{active ? "冻结" : "恢复"}</button></div></div>; })}</div></section>}
    {tab === "profiles" && <section className="detail-section"><header><div><h2>不可变 Profile 版本</h2><span>已存在 ID 不能原地修改</span></div></header><div className="admin-form profile-form"><label>Profile ID<input value={profileDraft.profile_id} onChange={(event) => setProfileDraft({ ...profileDraft, profile_id: event.target.value })} /></label><label>版本<input value={profileDraft.version} onChange={(event) => setProfileDraft({ ...profileDraft, version: event.target.value })} /></label><label>执行器类型<input value={profileDraft.executor_kind} onChange={(event) => setProfileDraft({ ...profileDraft, executor_kind: event.target.value })} /></label><label>输出契约<input value={profileDraft.output_schema} onChange={(event) => setProfileDraft({ ...profileDraft, output_schema: event.target.value })} /></label><label>平台<input value={profileDraft.platforms} onChange={(event) => setProfileDraft({ ...profileDraft, platforms: event.target.value })} /></label><label>所需能力<input value={profileDraft.required_capabilities} onChange={(event) => setProfileDraft({ ...profileDraft, required_capabilities: event.target.value })} /></label><label>CPU<input type="number" min="1" value={profileDraft.cpus} onChange={(event) => setProfileDraft({ ...profileDraft, cpus: Number(event.target.value) })} /></label><label>内存 MiB<input type="number" min="1" value={profileDraft.memory_mb} onChange={(event) => setProfileDraft({ ...profileDraft, memory_mb: Number(event.target.value) })} /></label><label>磁盘 MiB<input type="number" min="1" value={profileDraft.disk_mb} onChange={(event) => setProfileDraft({ ...profileDraft, disk_mb: Number(event.target.value) })} /></label><label>GPU<input type="number" min="0" value={profileDraft.gpus} onChange={(event) => setProfileDraft({ ...profileDraft, gpus: Number(event.target.value) })} /></label><button className="button button-primary" disabled={!profileDraft.profile_id || !profileDraft.output_schema} onClick={createProfile}>创建新版本</button></div><div className="profile-grid">{data.profiles.map((profile) => <article key={profile.profile_id}><Cpu size={17} /><h3>{profile.profile_id}</h3><p>{profile.output_schema}</p><dl><div><dt>version</dt><dd>{profile.version}</dd></div><div><dt>executor</dt><dd>{profile.executor_kind}</dd></div><div><dt>capabilities</dt><dd>{profile.required_capabilities?.join(", ") || "无"}</dd></div><div><dt>resources</dt><dd>{profile.default_resources.cpus} CPU · {profile.default_resources.memory_mb} MiB</dd></div></dl></article>)}</div></section>}
    {tab === "approvals" && <section className="detail-section"><header><div><h2>Solver Compatibility Approval</h2><span>绑定项目、执行环境、模板角色、Study、MeshPolicy 与 solver</span></div></header><fieldset disabled={!approvalReady || Boolean(approvalPending)} className="admin-form approval-form" style={{ border: 0, padding: 0, margin: 0 }}><label>项目<input value={approvalDraft.project_id} onChange={(event) => setApprovalDraft({ ...approvalDraft, project_id: event.target.value })} /></label><label>执行 Profile<input value={approvalDraft.execution_profile_id} onChange={(event) => setApprovalDraft({ ...approvalDraft, execution_profile_id: event.target.value })} /></label><label>COMSOL 版本<input value={approvalDraft.comsol_version} onChange={(event) => setApprovalDraft({ ...approvalDraft, comsol_version: event.target.value })} /></label><label>模板 SHA-256<input value={approvalDraft.template_sha256} onChange={(event) => setApprovalDraft({ ...approvalDraft, template_sha256: event.target.value.trim().toLowerCase() })} /></label>{approvalDraft.execution_profile_id === "workbench-comsol-study-v1" && <><label>正式 Runtime<input value={data.executionRuntime.runtime_version || ""} readOnly /></label><label>模板角色<input value={approvalDraft.template_role} onChange={(event) => setApprovalDraft({ ...approvalDraft, template_role: event.target.value })} /></label><label>允许 Study<input value={approvalDraft.allowed_study_kinds} onChange={(event) => setApprovalDraft({ ...approvalDraft, allowed_study_kinds: event.target.value })} placeholder="eigenfrequency, frequency_domain" /></label><label>哈希变化策略<select value={approvalDraft.template_hash_policy} onChange={(event) => setApprovalDraft({ ...approvalDraft, template_hash_policy: event.target.value })}><option value="warn_on_change">警告并审计</option><option value="exact">必须完全一致</option></select></label></>}<label>网格模式<select value={approvalDraft.mesh_mode} onChange={(event) => setApprovalDraft({ ...approvalDraft, mesh_mode: event.target.value })}><option value="auto_size">受控自动尺寸</option><option value="template_features">保留模板网格树</option></select></label><label>网格标签<input value={approvalDraft.mesh_tag} onChange={(event) => setApprovalDraft({ ...approvalDraft, mesh_tag: event.target.value })} /></label>{approvalDraft.mesh_mode === "auto_size" && <label>网格尺寸<input value={approvalDraft.mesh_size} onChange={(event) => setApprovalDraft({ ...approvalDraft, mesh_size: event.target.value })} /></label>}<button className="button button-primary" disabled={!approvalDraft.project_id || !/^[0-9a-f]{64}$/.test(approvalDraft.template_sha256) || (approvalDraft.execution_profile_id === "workbench-comsol-study-v1" && (!data.executionRuntime.runtime_version || !approvalDraft.template_role || !splitCsv(approvalDraft.allowed_study_kinds).length))} onClick={issueApproval}>签发审批</button></fieldset>{approvalPending && <div className="notice"><div><b>原 Solver 审批结果待核对</b><p>项目 {approvalPending.payload.project_id} · Profile {approvalPending.payload.execution_profile_id}。原签发内容已冻结，刷新不会自动重新签发。</p><button className="button small" disabled={mutating} onClick={() => recoverApproval()}>核对原审批结果</button><button className="button small" disabled={mutating} onClick={issueApproval}>重试原审批请求</button>{approvalPending.rejected && <button className="button small" disabled={mutating} onClick={() => { clearSolverApproval(sessionStorage, approvalPending); setApprovalPending(null); setNotice("已结束被拒绝的原审批请求，可以修改后重新签发。"); }}>结束被拒绝的审批请求</button>}</div></div>}<div className="approval-list">{data.approvals.map((approval) => <article key={approval.approval_id}><div><ShieldCheck size={17} /><span><b>{approval.project_id}{approval.template_role ? ` / ${approval.template_role}` : ""}</b><small>{approval.execution_profile_id} · COMSOL {approval.comsol_version}{approval.runtime_version ? ` · runtime ${approval.runtime_version}` : ""}</small></span></div><code>{approval.fingerprint}</code><span>{approval.allowed_study_kinds?.join(" / ") || [...approval.solver_variants].join(" / ")}</span><span>{approval.active ? "有效" : "已撤销"}</span>{approval.active && <button className="button small" onClick={() => revokeApproval(approval.approval_id)}>撤销</button>}</article>)}</div></section>}
    {tab === "templates" && <section className="detail-section"><header><div><h2>受信任 COMSOL 模板环境</h2><span>审批绑定项目、模板角色、Study 驱动和 solver；模板哈希变化只警告并审计</span></div></header><div className="template-environment-grid">{data.templateEnvironments.map(({ approval, observed_template_hashes: hashes, observed_study_kinds: kinds, output_contracts: outputs, recent_jobs: jobs }) => <article key={approval.approval_id}><header><FlaskConical size={17} /><div><b>{approval.project_id} / {approval.template_role}</b><small>{approval.active ? "有效" : "已撤销"} · {approval.template_hash_policy}</small></div></header><dl><div><dt>Study</dt><dd>{approval.allowed_study_kinds?.join(" · ") || "-"}</dd></div><div><dt>基线模板</dt><dd><code title={approval.template_sha256}>{approval.template_sha256?.slice(0, 16)}...</code></dd></div><div><dt>已观察哈希</dt><dd>{hashes.length}</dd></div><div><dt>输出契约</dt><dd>{outputs.length}</dd></div><div><dt>最近 Job</dt><dd>{jobs.length}</dd></div></dl>{hashes.length > 0 && <div className="hash-history">{hashes.map((hash) => <code key={hash} title={hash}>{hash.slice(0, 16)}...</code>)}</div>}{kinds.length > 0 && <p>{kinds.join(" · ")}</p>}{jobs.map((job) => <Link key={job.job_id} className="template-job-link" to={`/app/jobs/${job.job_id}`}>{job.job_id}<span>{job.warnings?.length ? `${job.warnings.length} 条警告` : "已审计"}</span></Link>)}</article>)}</div>{!data.templateEnvironments.length && <p className="empty-copy">尚无通用 Study 模板环境审批。</p>}</section>}
    {tab === "nodes" && <><section className="detail-section"><header><div><h2>节点准入与运行时</h2><span>preflight、候选状态和正式运行时</span></div></header><div className="runtime-grid">{runtimeGroups.map(({ machineId, config, machine }) => { const onboarding = data.onboarding.find((item) => item.profile.machine_id === machineId); const running = machine?.runtime_version || ""; const candidate = Boolean(running && config.runtime_version && running !== config.runtime_version); const previous = config.execution_provenance?.previous_runtime_version || ""; return <article key={machineId}><header><Server size={17} /><div><b>{machine?.display_name || machineId}</b><small>{machineId}</small></div></header><dl><div><dt>running</dt><dd>{running || "-"}</dd></div><div><dt>formal</dt><dd>{config.runtime_version || "-"}</dd></div><div><dt>状态</dt><dd>{candidate ? "候选运行中" : "正式一致"}</dd></div><div><dt>preflight</dt><dd>{onboarding?.latest_run?.status || "未登记"}</dd></div><div><dt>operational</dt><dd>{config.operational_execution || "pending"}</dd></div><div><dt>target / max</dt><dd>{config.target_concurrent_units} / {config.max_concurrent_units}</dd></div></dl><footer><Link className="button small" to={`/app/machines/${machineId}?tab=config`}>查看配置</Link>{onboarding && <button className="button small" onClick={() => runPreflight(machineId)}>运行只读 preflight</button>}{candidate && <button className="button small" onClick={() => setRuntimeControl({ machineId, action: "promote_runtime" })}>晋升候选</button>}{!candidate && previous && previous !== running && <button className="button small" onClick={() => setRuntimeControl({ machineId, action: "rollback_runtime" })}>回滚上一版本</button>}</footer></article>; })}</div></section><section className="detail-section narrow-section"><header><div><h2>历史节点登记</h2><span>新成员安装请使用上方成员邀请；这里保留已有节点登记记录。</span></div></header><div className="deep-list">{data.enrollments.map((item) => <div key={item.enrollment_id}><KeyRound size={15} /><span><b>{item.owner_user_id}</b><small>{item.used_at ? `已用于 ${item.machine_id}` : `有效至 ${time(item.expires_at)}`}</small></span></div>)}</div></section></>}
    {tab === "capacity" && <section className="detail-section"><header><div><h2>外部计算负载与容量</h2><span>全局默认；更改后由 Control Plane 在真实遥测上统一判定</span></div></header><div className="capacity-policy-intro"><Gauge size={18} /><p>CPU/GPU 表示 Network 进程树之外的真实计算活动，与具体仿真软件无关。外部程序的驻留内存只参与每个 Unit 的硬资源校验，不单独触发降容。管理员临时覆盖仍不能越过静态硬上限、Profile、内存、磁盘、solver 或在线门槛。</p></div><div className="admin-form capacity-policy-form"><label>外部 CPU 阈值 %<input type="number" min="0" max="100" step="0.5" value={pressureDraft.external_cpu_threshold_percent} onChange={(event) => setPressureDraft({ ...pressureDraft, external_cpu_threshold_percent: Number(event.target.value) })} /></label><label>外部 GPU 阈值 %<input type="number" min="0" max="100" step="0.5" value={pressureDraft.external_gpu_threshold_percent} onChange={(event) => setPressureDraft({ ...pressureDraft, external_gpu_threshold_percent: Number(event.target.value) })} /></label><label>内存判定模式<select value={pressureDraft.memory_mode} onChange={(event) => setPressureDraft({ ...pressureDraft, memory_mode: event.target.value })}><option value="resource_gate_only">仅资源硬门槛</option><option value="low_headroom">外部占用且余量不足</option><option value="absolute">外部绝对占用</option></select></label><label>外部内存阈值 MiB<input type="number" min="0" step="256" value={pressureDraft.external_memory_threshold_mb} onChange={(event) => setPressureDraft({ ...pressureDraft, external_memory_threshold_mb: Number(event.target.value) })} /></label><label>可用内存下限 MiB<input type="number" min="0" step="256" disabled={pressureDraft.memory_mode !== "low_headroom"} value={pressureDraft.available_memory_floor_mb} onChange={(event) => setPressureDraft({ ...pressureDraft, available_memory_floor_mb: Number(event.target.value) })} /></label><label>进入迟滞 秒<input type="number" min="0" max="3600" value={pressureDraft.enter_after_seconds} onChange={(event) => setPressureDraft({ ...pressureDraft, enter_after_seconds: Number(event.target.value) })} /></label><label>解除迟滞 秒<input type="number" min="0" max="7200" value={pressureDraft.clear_after_seconds} onChange={(event) => setPressureDraft({ ...pressureDraft, clear_after_seconds: Number(event.target.value) })} /></label><label>受压时派发上限<input type="number" min="0" max="64" value={pressureDraft.pressured_dispatch_cap} onChange={(event) => setPressureDraft({ ...pressureDraft, pressured_dispatch_cap: Number(event.target.value) })} /></label><label>遥测过期新派发上限<select value={pressureDraft.telemetry_stale_cap} onChange={(event) => setPressureDraft({ ...pressureDraft, telemetry_stale_cap: Number(event.target.value) })}><option value={0}>0 · 阻止</option><option value={1}>1 · 保守允许</option></select></label><label>管理员覆盖最长 分钟<input type="number" min="1" max="120" value={pressureDraft.max_override_minutes} onChange={(event) => setPressureDraft({ ...pressureDraft, max_override_minutes: Number(event.target.value) })} /></label><h3 className="form-span">遥测采样策略</h3><label>采样间隔 秒<input type="number" min="1" max="60" value={telemetryDraft.sample_interval_s} onChange={(event) => setTelemetryDraft({ ...telemetryDraft, sample_interval_s: Number(event.target.value) })} /></label><label>CPU 窗口 秒<input type="number" min="1" max="300" value={telemetryDraft.cpu_sample_window_s} onChange={(event) => setTelemetryDraft({ ...telemetryDraft, cpu_sample_window_s: Number(event.target.value) })} /></label><label>峰值窗口 秒<input type="number" min="1" max="900" value={telemetryDraft.peak_window_s} onChange={(event) => setTelemetryDraft({ ...telemetryDraft, peak_window_s: Number(event.target.value) })} /></label><label>采样超时 秒<input type="number" min="1" max="30" value={telemetryDraft.sample_timeout_s} onChange={(event) => setTelemetryDraft({ ...telemetryDraft, sample_timeout_s: Number(event.target.value) })} /></label><label>过期判定 秒<input type="number" min="5" max="3600" value={telemetryDraft.stale_after_s} onChange={(event) => setTelemetryDraft({ ...telemetryDraft, stale_after_s: Number(event.target.value) })} /></label><label className="form-span">诊断进程关键词<input value={(telemetryDraft.external_process_names || []).join(", ")} onChange={(event) => setTelemetryDraft({ ...telemetryDraft, external_process_names: splitCsv(event.target.value) })} /></label><button className="button button-primary" disabled={mutating || !telemetryDraft.external_process_names?.length} onClick={savePressurePolicy}>保存容量与遥测策略</button></div></section>}
    {tab === "breakglass" && <section className="detail-section narrow-section"><header><div><h2>Break-glass PIN</h2><span>独立 scrypt 强哈希，不记录明文</span></div><span>{data.breakglass.configured ? `已配置 · ${time(data.breakglass.updated_at)}` : "未配置"}</span></header><div className="pin-rotate"><Bell size={18} /><div><p>PIN 只用于单机主机级 COMSOL 紧急终止。浏览器不会保存该值。</p><label>新 PIN<input type="password" value={pin} onChange={(event) => setPin(event.target.value)} autoComplete="new-password" /></label><button className="button button-primary" disabled={mutating || pin.length < 8} onClick={rotatePin}>轮换 PIN</button></div></div></section>}
    {tab === "capacity" && <section className="detail-section"><header><div><h2>Network 资源自治</h2><span>按 Profile 解析资源；运行中 Attempt 的资源保持冻结</span></div></header><ResourcePolicyEditor profiles={data.profiles} policies={data.settings.resource_policies || {}} setError={setError} setNotice={setNotice} onSaved={load} /></section>}
    </>}
    </fieldset>
    {runtimeControl && <RuntimeControlDialog {...runtimeControl} onClose={() => setRuntimeControl(null)} onComplete={async () => { await load(tabResources.nodes); await onGlobalRefresh?.(); }} />}
  </main>;
}
