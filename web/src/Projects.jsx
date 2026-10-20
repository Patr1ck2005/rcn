import { useMemo, useState } from "react";
import {
  AlertTriangle, Boxes, CheckCircle2, Clock3, LockKeyhole,
  Plus, RefreshCw, ShieldCheck, UserPlus, Users,
} from "lucide-react";

import { api } from "./api";
import { MyPersonalAccess } from "./PersonalAccess";
import { useMutationGuard } from "./useMutationGuard";
import { usePageRefresh } from "./usePageRefresh";
import { DataLoadState } from "./AsyncState";
import { HelpLink } from "./HelpSystem";

const statusText = {
  requested: "登记申请", approved: "已登记", rejected: "已拒绝",
  cancelled: "已取消", active: "可提交", pending: "等待确认", frozen: "已冻结",
};

function Restriction({ restriction, children }) {
  return <div className="restriction-panel"><LockKeyhole size={18} /><div>
    <b>{restriction?.message || "该功能存在，但当前身份/项目/机器尚未获得所需权限。"}</b>
    <p>{children || restriction?.next_action || "请向对应 owner 或管理员申请。"}</p>
    {restriction?.reason_code && <code>{restriction.reason_code}</code>}
  </div></div>;
}

export default function Projects({ actorId, roles = [], onGlobalRefresh }) {
  const [data, setData] = useState({ projects: [], registrations: [], profiles: [], enrollments: [] });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [draft, setDraft] = useState({ project_id: "", display_name: "", purpose: "", requested_profiles: ["workbench-comsol-study-v1"] });
  const [trustedDrafts, setTrustedDrafts] = useState({});
  const machineOwner = roles.includes("machine_owner") || roles.includes("admin");
  const mutation = useMutationGuard();
  const [personalPolicy, setPersonalPolicy] = useState(null);
  const [readErrors, setReadErrors] = useState({});
  const load = usePageRefresh(async ({ signal, isCurrent }) => {
    setRefreshing(true);
    await Promise.allSettled([
      ["projects", "/v1/projects"], ["registrations", "/v1/project-registrations"], ["profiles", "/v1/profiles"],
      ...(machineOwner ? [["enrollments", "/v1/me/enrollments"]] : []),
    ].map(async ([key, path]) => {
      try {
        const value = await api(path, { signal });
        if (!isCurrent()) return;
        setData((current) => ({ ...current, [key]: value })); setReadErrors((current) => ({ ...current, [key]: "" }));
      } catch (caught) { if (isCurrent()) setReadErrors((current) => ({ ...current, [key]: caught.message })); }
    }));
    if (isCurrent()) { setLoading(false); setRefreshing(false); }
  }, { key: machineOwner, initial: true, resources: ["projects", "profiles", "enrollments"] });

  const allowedProfiles = useMemo(
    () => data.profiles.filter((profile) => profile.profile_id !== "project-worker-v1"),
    [data.profiles],
  );
  const submitRegistration = (event) => mutation.run(async () => {
    event.preventDefault(); setError(""); setNotice("");
    try {
      await api("/v1/project-registrations", { method: "POST", body: JSON.stringify(draft) });
      setDraft({ project_id: "", display_name: "", purpose: "", requested_profiles: ["workbench-comsol-study-v1"] });
      setNotice(personalPolicy?.approved && personalPolicy?.auto_project ? "项目登记已提交，按个人提交权限核对后即可使用。" : "项目登记已提交，可在个人权限或已有项目授权范围内使用。");
      await load(true); await onGlobalRefresh?.();
    } catch (caught) { setError(caught.message); }
  });
  const addTrusted = (projectId) => mutation.run(async () => {
    const userId = (trustedDrafts[projectId] || "").trim();
    if (!userId) return;
    setError("");
    try {
      await api(`/v1/projects/${projectId}/trusted-users/${encodeURIComponent(userId)}`, { method: "PUT" });
      setTrustedDrafts((current) => ({ ...current, [projectId]: "" }));
      setNotice(`已将 ${userId} 加入 ${projectId} 的可信提交者。`);
      await load(true);
    } catch (caught) { setError(caught.message); }
  });
  const removeTrusted = (projectId, userId) => mutation.run(async () => {
    setError("");
    try {
      await api(`/v1/projects/${projectId}/trusted-users/${encodeURIComponent(userId)}`, { method: "DELETE" });
      setNotice(`已移除 ${userId} 的项目提交授权。`); await load(true);
    } catch (caught) { setError(caught.message); }
  });

  if (loading) return <main className="app-page"><DataLoadState status="loading" label="正在加载项目与准入权限" /></main>;
  return <main className="app-page projects-page">
    <div className="page-title"><div><span>PROJECTS / CONTROLLED ONBOARDING</span><h1>项目与接入</h1><p>登记声明式项目、管理可信提交者，并查看已有机器接入记录</p></div><div className="page-actions"><HelpLink topic="projectOnboarding" /><button className="button" disabled={refreshing} onClick={() => load(true)}><RefreshCw size={16} className={refreshing ? "spin" : ""} />刷新</button></div></div>
    {(error || Object.values(readErrors).some(Boolean)) && <div className="inline-error"><AlertTriangle size={16} />{[error, ...Object.entries(readErrors).filter(([, value]) => value).map(([key, value]) => `${key}：${value}`)].filter(Boolean).join("；")}</div>}
    {notice && <div className="notice"><CheckCircle2 size={16} />{notice}</div>}

    <MyPersonalAccess onPolicy={setPersonalPolicy} />
    <section className="detail-section"><header><div><h2>我的项目</h2><span>个人权限覆盖本人项目；owner 管理项目内可信提交者</span></div><span>{data.projects.length} 个已授权</span></header>
      <div className="project-access-grid">{data.projects.map((project) => {
        const owner = project.owner_user_id === actorId;
        return <article key={project.project_id}><header><Boxes size={17} /><div><b>{project.project_id}</b><small>{statusText[project.status] || project.status}</small></div></header>
          <dl><div><dt>Profile</dt><dd>{project.allowed_profiles?.join(" · ") || "等待批准"}</dd></div><div><dt>配额</dt><dd>{project.max_queued_units} queued / {project.max_running_units} running</dd></div><div><dt>Priority ceiling</dt><dd>{project.priority_ceiling ?? 0}</dd></div><div><dt>Owner</dt><dd>{project.owner_user_id}</dd></div></dl>
          {project.status === "frozen" && <Restriction restriction={{ reason_code: "project_frozen" }}>{project.frozen_reason || "管理员已冻结项目；现有记录保留，新提交暂停。"}</Restriction>}
          <div className="trusted-users"><b>可信提交者</b>{(project.authorized_user_ids || []).map((userId) => <span key={userId}><Users size={14} />{userId}{owner && <button disabled={mutation.busy} title={`移除 ${userId}`} onClick={() => removeTrusted(project.project_id, userId)}>移除</button>}</span>)}{!(project.authorized_user_ids || []).length && <small>当前仅 owner 可提交</small>}</div>
          {owner && <div className="inline-compose"><label>添加已有用户<input disabled={mutation.busy} value={trustedDrafts[project.project_id] || ""} onChange={(event) => setTrustedDrafts((current) => ({ ...current, [project.project_id]: event.target.value }))} placeholder="用户 ID" /></label><button className="button small" disabled={mutation.busy} onClick={() => addTrusted(project.project_id)}><UserPlus size={15} />添加</button></div>}
        </article>;
      })}{!data.projects.length && (personalPolicy?.approved && personalPolicy?.auto_project && !personalPolicy?.paused ? <p>当前还没有登记的项目；可以直接登记本人项目并按个人权限提交。</p> : <Restriction restriction={{ reason_code: "project_grant_missing" }}>当前还没有登记的项目。已开通个人提交权限的成员可直接登记本人项目。</Restriction>)}</div>
    </section>

    <section className="detail-section"><header><div><h2>登记新项目</h2><span>Network 只接受固定、审计、声明式 Profile，不执行项目上传的 Python</span></div></header>
      <form className="admin-form project-registration-form" onSubmit={submitRegistration}><label>项目 ID<input disabled={mutation.busy} required pattern="[A-Za-z0-9][A-Za-z0-9._-]*" value={draft.project_id} onChange={(event) => setDraft({ ...draft, project_id: event.target.value })} /></label><label>显示名称<input disabled={mutation.busy} required value={draft.display_name} onChange={(event) => setDraft({ ...draft, display_name: event.target.value })} /></label><label className="form-span">用途<textarea disabled={mutation.busy} required value={draft.purpose} onChange={(event) => setDraft({ ...draft, purpose: event.target.value })} /></label><label className="form-span">申请 Profile<select disabled={mutation.busy} multiple value={draft.requested_profiles} onChange={(event) => setDraft({ ...draft, requested_profiles: [...event.target.selectedOptions].map((option) => option.value) })}>{allowedProfiles.map((profile) => <option key={profile.profile_id} value={profile.profile_id}>{profile.profile_id}</option>)}</select></label><button className="button button-primary" disabled={mutation.busy || !draft.requested_profiles.length}><Plus size={16} />登记项目</button></form>
      <div className="registration-timeline">{data.registrations.map((item) => <article key={item.registration_id}><Clock3 size={16} /><div><b>{item.project_id}</b><span>{statusText[item.status] || item.status}</span><small>{item.review_reason || "按个人权限或已有项目授权核对"}</small></div></article>)}{!data.registrations.length && <p>尚无登记申请。</p>}</div>
    </section>

    <section className="detail-section"><header><div><h2>我的机器接入记录</h2><span>新机器请向管理员领取私密 v2 成员邀请，使用通用安装包接入。</span></div></header>
      {machineOwner ? <div className="registration-timeline">{data.enrollments.map((item) => <article key={item.enrollment_id}><ShieldCheck size={16} /><div><b>{item.machine_id || "等待机器使用"}</b><span>{item.used_at ? "已登记" : "历史准入申请"}</span><small>{item.used_at ? "机器当前准入状态以节点详情为准" : `原有效期至 ${new Date(item.expires_at).toLocaleString("zh-CN", { hour12: false })}`}</small></div></article>)}{!data.enrollments.length && <p>暂无历史接入记录。新安装统一使用管理员签发的私密 v2 成员邀请。</p>}</div> : <p>机器接入使用管理员签发的私密 v2 成员邀请；计算参与权限与项目提交权限分别管理。</p>}
    </section>
  </main>;
}
