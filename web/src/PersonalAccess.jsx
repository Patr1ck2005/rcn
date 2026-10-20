import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import { DataLoadState, RefreshStatus } from "./AsyncState";
import { usePageRefresh } from "./usePageRefresh";

export const quotaModeText = { shadow: "影子记账", unlimited: "不限额度", metered: "按额度使用" };
export function submissionPolicyDraft(personId, policy) {
  return { approved: false, paused: false, auto_project: true, allowed_profiles: [],
    max_queued_units: 2000, max_running_units: 4, priority_ceiling: 0, quota_mode: "shadow", ...policy, person_id: personId };
}
const hours = (value) => Number.isFinite(Number(value)) ? Number(value).toLocaleString("zh-CN", { maximumFractionDigits: 3 }) : "未知";

export function PersonalAccessSummary({ access, credits }) {
  const policy = access?.policy;
  return <>
    {access && <div className="notice"><div><b>个人提交权限：{policy ? policy.paused ? "已暂停" : policy.approved ? "已开通" : "等待开通" : "沿用已有项目授权"}</b>
      {policy && <p>适用本人项目 · 排队 {access.usage?.queued_units ?? 0}/{policy.max_queued_units} · 运行 {access.usage?.running_units ?? 0}/{policy.max_running_units} · 优先级上限 {policy.priority_ceiling} · {quotaModeText[policy.quota_mode] || policy.quota_mode}<br />Profile：{policy.allowed_profiles?.join(" · ") || "尚未开放"}{policy.auto_project && " · 新项目自动登记"}</p>}</div></div>}
    {credits && <div className="project-access-grid"><article><h3>我的计算额度</h3><dl>
      <div><dt>可用 CPU 核时</dt><dd>{hours(credits.available_cpu_core_hours)}</dd></div><div><dt>可用 GPU 设备时</dt><dd>{hours(credits.available_gpu_device_hours)}</dd></div>
      <div><dt>已预留 CPU / GPU</dt><dd>{hours(credits.reserved_cpu_core_hours)} / {hours(credits.reserved_gpu_device_hours)}</dd></div>
    </dl><p>{credits.settings?.metering_enabled ? "额度计量已启用；是否扣减还取决于个人额度模式。" : "当前为影子记账，不因余额阻止派发。"}</p>
      {credits.shadow_balance && <p>影子记录（不能兑换）：CPU {hours(credits.shadow_balance.cpu_core_hours)} 核时 · GPU {hours(credits.shadow_balance.gpu_device_hours)} 设备时；预留 {hours(credits.shadow_balance.reserved_cpu_core_hours)} / {hours(credits.shadow_balance.reserved_gpu_device_hours)}。开启计量不会自动转为上方的正式额度。</p>}
      {credits.legacy_isolation?.present && <p>旧账记录（不能兑换）：CPU {hours(credits.legacy_balance?.cpu_core_hours)} 核时 · GPU {hours(credits.legacy_balance?.gpu_device_hours)} 设备时。需要管理员核对，不会自动计入正式额度。</p>}
      {!!credits.pending_review_attempt_ids?.length && <p>有 {credits.pending_review_attempt_ids.length} 个 Attempt 等待核对，预留额度仍保留。</p>}</article>
      <article><h3>互助池</h3><p>按实际使用的 CPU 核时和 GPU 设备时分别记账；正式记账时贡献方获得对应额度，影子期只保留模拟记录。</p><h3>免费空闲池</h3><p>由机器所有者单独同意开放；不扣使用者额度，也不产生贡献收入。</p></article></div>}
  </>;
}

export function MyPersonalAccess({ onPolicy, enabled = true }) {
  const [data, setData] = useState({});
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(true);
  const load = usePageRefresh(async ({ signal, isCurrent }) => {
    setLoading(true);
    await Promise.allSettled([["access", "/v1/me/submission-policy"], ["credits", "/v1/me/compute-credits"]].map(async ([key, path]) => {
      try {
        const value = await api(path, { signal });
        if (!isCurrent()) return;
        setData((current) => ({ ...current, [key]: value })); setErrors((current) => ({ ...current, [key]: "" }));
        if (key === "access") onPolicy?.(value.policy);
      } catch (caught) { if (isCurrent()) setErrors((current) => ({ ...current, [key]: caught.message })); }
    }));
    if (isCurrent()) setLoading(false);
  }, { initial: true, enabled, resources: ["personal-access", "credits"] });
  return <section className="detail-section"><header><div><h2>我的提交权限与额度</h2><span>个人权限、项目归属与机器所有者同意分别生效</span></div><button className="button small" disabled={loading} onClick={load}>刷新权限与额度</button></header>
    {!enabled ? <p>连接中心后可读取个人权限与额度。</p> : <><RefreshStatus visible={loading} />{!data.access && !data.credits && loading && <DataLoadState label="正在读取个人权限与额度" />}</>}
    <PersonalAccessSummary {...data} />{Object.entries(errors).filter(([, error]) => error).map(([key, error]) => <p key={key} className="inline-error" role="alert">{key === "access" ? "个人提交权限" : "个人额度"}读取失败：{error}</p>)}
  </section>;
}

export function PersonPolicyEditor({ users = [], profiles = [] }) {
  const people = users.filter((user) => user.active && user.roles?.some((role) => ["member", "admin"].includes(role)));
  const [selection, setSelection] = useState("");
  const personId = selection || people[0]?.user_id || "";
  const [draft, setDraft] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const inFlight = useRef(false);
  const baseline = useRef(null);
  const currentPerson = useRef(personId);
  currentPerson.current = personId;
  const load = usePageRefresh(async ({ signal, isCurrent }) => {
    try {
      const value = await api(`/v1/admin/people/${encodeURIComponent(personId)}/submission-policy`, { signal });
      if (!isCurrent()) return;
      const next = submissionPolicyDraft(personId, value.policy);
      setDraft((current) => !current || current.person_id !== personId || JSON.stringify(current) === JSON.stringify(baseline.current) ? next : current);
      baseline.current = next; setError("");
    } catch (caught) { if (isCurrent()) setError(caught.message); }
  }, { key: personId, initial: true, enabled: Boolean(personId), resources: ["personal-access"] });
  useEffect(() => { setDraft(null); setError(""); setNotice(""); }, [personId]);
  const save = async (event) => {
    event.preventDefault();
    if (inFlight.current || !draft || draft.person_id !== personId) return;
    const id = personId;
    inFlight.current = true; setBusy(true); setError(""); setNotice("");
    try {
      const value = await api(`/v1/admin/people/${encodeURIComponent(id)}/submission-policy`, { method: "PUT", body: JSON.stringify(draft) });
      if (currentPerson.current !== id) return;
      const next = submissionPolicyDraft(id, value);
      setDraft(next); baseline.current = next; setNotice("个人提交权限已保存，适用该成员的全部项目。");
    } catch (caught) { if (currentPerson.current === id) setError(caught.message); }
    finally { inFlight.current = false; setBusy(false); }
  };
  const change = (key, value) => setDraft((current) => ({ ...current, [key]: value }));
  return <section className="detail-section"><header><div><h2>个人提交权限</h2><span>按成员开通 Profile、并发与额度模式；机器贡献角色单独管理</span></div></header>
    <label>选择提交成员<select aria-label="选择提交成员" value={personId} disabled={busy} onChange={(event) => setSelection(event.target.value)}>{people.map((user) => <option key={user.user_id} value={user.user_id}>{user.display_name || user.user_id} · {user.user_id}</option>)}</select></label>
    {error && <p role="alert" className="inline-error">{error}</p>}{notice && <p role="status">{notice}</p>}
    {personId && !draft && !error && <DataLoadState label="正在读取成员提交权限" />}
    {draft?.person_id === personId && <form className="admin-form" onSubmit={save}>
      <label>开通提交<input type="checkbox" checked={draft.approved} disabled={busy} onChange={(event) => change("approved", event.target.checked)} /></label>
      <label>暂停提交<input type="checkbox" checked={draft.paused} disabled={busy} onChange={(event) => change("paused", event.target.checked)} /></label>
      <label>自动登记本人新项目<input type="checkbox" checked={draft.auto_project} disabled={busy} onChange={(event) => change("auto_project", event.target.checked)} /></label>
      <label>允许的 Profile<select aria-label="个人允许的 Profile" multiple value={draft.allowed_profiles} disabled={busy} onChange={(event) => change("allowed_profiles", [...event.target.selectedOptions].map((option) => option.value))}>{profiles.map((profile) => <option key={profile.profile_id} value={profile.profile_id}>{profile.profile_id}</option>)}</select></label>
      {[["max_queued_units", "个人排队单元上限", 0, undefined], ["max_running_units", "个人运行单元上限", 0, undefined], ["priority_ceiling", "个人优先级上限", -100, 100]].map(([key, title, min, max]) => <label key={key}>{title}<input aria-label={title} type="number" required min={min} max={max} step="1" disabled={busy} value={draft[key]} onChange={(event) => change(key, Number(event.target.value))} /></label>)}
      <label>额度模式<select aria-label="个人额度模式" value={draft.quota_mode} disabled={busy} onChange={(event) => change("quota_mode", event.target.value)}>{Object.entries(quotaModeText).map(([key, text]) => <option key={key} value={key}>{text}</option>)}</select></label>
      <button className="button button-primary" disabled={busy}>保存个人提交权限</button><button type="button" className="button" disabled={busy} onClick={load}>核对当前权限</button>
    </form>}
  </section>;
}
