import { useMutationGuard } from "./useMutationGuard";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { CheckCircle2, Clock3, Plus, RefreshCw, Save, Trash2 } from "lucide-react";

import { api, currentIdentityEpoch } from "./api";
import { DataLoadState, RefreshStatus } from "./AsyncState";

const weekdays = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"];
const numericPolicyFields = [
  ["keyboard_idle_min_s", "键鼠空闲门槛", "秒", 0],
  ["non_pool_cpu_max_percent", "非 Network CPU 上限", "%", 0, 100],
  ["cpu_window_s", "CPU 判定窗口", "秒", 1],
  ["memory_reserve_mb", "内存预留", "MiB", 0],
  ["max_cpus", "CPU 上限", "线程", 1],
  ["max_memory_mb", "内存使用上限", "MiB", 256],
  ["max_gpus", "GPU 上限", "张", 0],
  ["max_concurrent_units", "所有者并发上限", "Unit", 1],
];

export function previewCpuBudget(machine, policy) {
  const total = Math.max(0, Math.floor(Number(machine.total_cpus) || 0));
  let cap = Math.max(0, Math.min(total, Math.floor(Number(policy.max_cpus) || 0)));
  if (policy.shared_machine) {
    const reserve = Math.max(25, Math.min(100, Number(policy.cpu_reserve_percent) || 25));
    cap = Math.min(cap, Math.floor(total * (100 - reserve) / 100));
  }
  if (policy.member_execution_limit) cap = Math.min(cap, policy.member_execution_limit.max_cpus);
  return Math.max(0, cap);
}

function policyDraft(policy) {
  const windows = Object.fromEntries(
    weekdays.map((_, day) => [day, (policy.weekly_windows?.[day] || []).map((window) => ({ ...window }))]),
  );
  return {
    owner_mode: policy.owner_mode || "paused",
    shared_machine: policy.shared_machine === true,
    cpu_reserve_percent: Number(policy.cpu_reserve_percent ?? 25),
    timezone: policy.timezone || "Asia/Shanghai",
    unrestricted: !Object.values(windows).some((items) => items.length),
    windows,
    values: Object.fromEntries(numericPolicyFields.map(([field]) => [field, Number(policy[field] ?? 0)])),
  };
}

export function policyEditorState(machineId, policy, revisionHash) {
  return { machineId, policy, revisionHash, draft: policyDraft(policy) };
}

export function reconcilePolicyEditor(current, machineId, policy, revisionHash) {
  if (current.machineId !== machineId || JSON.stringify(current.draft) === JSON.stringify(policyDraft(current.policy))) {
    return policyEditorState(machineId, policy, revisionHash);
  }
  // A dirty draft retains the exact policy revision from which it was made.
  return current;
}

function executionDraft(config) {
  const resolvedConfig = config || {};
  return {
    disk_reserve_gib: Number(resolvedConfig.disk_reserve_gib ?? 50),
    success_retention_days: Number(resolvedConfig.success_retention_days ?? 3),
    failure_retention_days: Number(resolvedConfig.failure_retention_days ?? 7),
    poll_interval_s: Number(resolvedConfig.poll_interval_s ?? 15),
    profile_concurrency_limits: { ...(resolvedConfig.profile_concurrency_limits || {}) },
  };
}

function ScheduleEditor({ draft, setDraft, disabled }) {
  const changeWindow = (day, index, field, value) => setDraft((current) => ({
    ...current,
    windows: {
      ...current.windows,
      [day]: current.windows[day].map((window, itemIndex) => (
        itemIndex === index ? { ...window, [field]: value } : window
      )),
    },
  }));
  const addWindow = (day) => setDraft((current) => ({
    ...current,
    unrestricted: false,
    windows: { ...current.windows, [day]: [...current.windows[day], { start: "09:00", end: "18:00" }] },
  }));
  const removeWindow = (day, index) => setDraft((current) => ({
    ...current,
    windows: { ...current.windows, [day]: current.windows[day].filter((_, itemIndex) => itemIndex !== index) },
  }));
  return <>
    <div className="schedule-toolbar">
      <label className="toggle"><input type="checkbox" checked={draft.unrestricted} disabled={disabled} onChange={(event) => setDraft((current) => ({ ...current, unrestricted: event.target.checked }))} />不限制运行时段</label>
      <label>时区<input aria-label="调度时区" list="rcn-timezones" value={draft.timezone} disabled={disabled || draft.unrestricted} onChange={(event) => setDraft((current) => ({ ...current, timezone: event.target.value }))} /></label>
      <datalist id="rcn-timezones"><option value="Asia/Shanghai" /><option value="UTC" /><option value="Asia/Tokyo" /><option value="Europe/Berlin" /><option value="America/Los_Angeles" /></datalist>
    </div>
    {!draft.unrestricted && <div className="weekly-schedule">{weekdays.map((name, day) => <div className="schedule-day" key={name}>
      <strong>{name}</strong>
      <div className="schedule-windows">{draft.windows[day].map((window, index) => <div className="schedule-window" key={`${day}-${index}`}>
        <input aria-label={`${name} 开始 ${index + 1}`} type="time" value={window.start} disabled={disabled} onChange={(event) => changeWindow(day, index, "start", event.target.value)} />
        <span>至</span>
        <input aria-label={`${name} 结束 ${index + 1}`} type="time" value={window.end} disabled={disabled} onChange={(event) => changeWindow(day, index, "end", event.target.value)} />
        <button className="icon-button" title={`删除${name}时间段`} disabled={disabled} onClick={() => removeWindow(day, index)}><Trash2 size={15} /></button>
      </div>)}{!draft.windows[day].length && <span className="schedule-closed">不开放</span>}</div>
      <button className="icon-button" title={`添加${name}时间段`} disabled={disabled} onClick={() => addWindow(day)}><Plus size={15} /></button>
    </div>)}</div>}
  </>;
}

export function MachinePolicyEditor({ machine, policy, policyRevisionHash, config, canEdit, onSaved }) {
  const resolvedConfig = config || {};
  const [editor, setEditor] = useState(() => policyEditorState(machine.machine_id, policy, policyRevisionHash));
  const currentEditor = editor.machineId === machine.machine_id ? editor : policyEditorState(machine.machine_id, policy, policyRevisionHash);
  const draft = currentEditor.draft;
  const setDraft = (update) => setEditor((current) => {
    const base = current.machineId === machine.machine_id ? current : policyEditorState(machine.machine_id, policy, policyRevisionHash);
    return { ...base, draft: typeof update === "function" ? update(base.draft) : update };
  });
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [saving, setSaving] = useState(false);
  const mutation = useMutationGuard();
  const saveScope = JSON.stringify([machine.machine_id, currentIdentityEpoch()]);
  const latestScope = useRef(saveScope);
  latestScope.current = saveScope;
  useEffect(() => { setSaving(false); setError(""); setNotice(""); }, [saveScope]);
  useEffect(() => {
    setEditor((current) => reconcilePolicyEditor(current, machine.machine_id, policy, policyRevisionHash));
  }, [policy, machine.machine_id, policyRevisionHash]);
  const revisionChanged = Boolean(currentEditor.revisionHash && policyRevisionHash && currentEditor.revisionHash !== policyRevisionHash);
  const limits = {
    max_cpus: machine.total_cpus,
    max_memory_mb: machine.total_memory_mb,
    max_gpus: machine.total_gpus,
    max_concurrent_units: resolvedConfig.max_concurrent_units,
  };
  const save = () => mutation.run(async () => {
    if (!/^[a-f0-9]{64}$/i.test(currentEditor.revisionHash || "")) {
      setError("未取得机器策略版本，请重新读取后保存。");
      return;
    }
    const windows = draft.unrestricted ? {} : Object.fromEntries(
      Object.entries(draft.windows).filter(([, items]) => items.length),
    );
    if (!draft.unrestricted && !Object.keys(windows).length) {
      setError("限制运行时段时至少需要一个时间段");
      return;
    }
    setSaving(true); setError(""); setNotice("");
    try {
      const result = await api(`/v1/machines/${machine.machine_id}/policy`, {
        method: "PUT",
        body: JSON.stringify({
          ...currentEditor.policy,
          expected_policy_payload_sha256: currentEditor.revisionHash,
          ...draft.values,
          owner_mode: draft.owner_mode,
          shared_machine: draft.shared_machine,
          cpu_reserve_percent: draft.cpu_reserve_percent,
          timezone: draft.timezone.trim(),
          weekly_windows: windows,
        }),
      });
      if (latestScope.current !== saveScope) return;
      setEditor(policyEditorState(machine.machine_id, result, currentEditor.revisionHash));
      setNotice("机器策略已保存");
      await onSaved?.();
    } catch (caught) {
      if (latestScope.current !== saveScope) return;
      setError(caught.reasonCode === "machine_policy_revision_conflict" ? "机器策略已变化，请读取最新策略后重新编辑。" : caught.message);
      if (caught.reasonCode === "machine_policy_revision_conflict") {
        try { await onSaved?.(); } catch { /* Keep the explicit policy conflict visible. */ }
      }
    }
    finally { if (latestScope.current === saveScope) setSaving(false); }
  });
  return <>
    <section className="detail-section" aria-label="共享机器 CPU 预算">
      <header><div><h2>共享机器算力预留</h2><span>线程预算，不是操作系统 CPU 时间配额</span></div></header>
      <label className="toggle"><input type="checkbox" checked={draft.shared_machine} disabled={!canEdit || saving || policy.shared_machine === true} onChange={(event) => setDraft((current) => ({ ...current, shared_machine: event.target.checked }))} />这台机器还有其他使用者</label>
      {draft.shared_machine && <label>至少留给其他用户<input aria-label="CPU 预留百分比" type="number" min="25" max="100" step="1" value={draft.cpu_reserve_percent} disabled={!canEdit || saving} onChange={(event) => setDraft((current) => ({ ...current, cpu_reserve_percent: Number(event.target.value) }))} />%</label>}
      <p>本次设置的网络线程预算：{previewCpuBudget(machine, { ...policy, ...draft.values, shared_machine: draft.shared_machine, cpu_reserve_percent: draft.cpu_reserve_percent })} / {machine.total_cpus}。共享标记不能在普通策略编辑中移除；新增或收紧预留前须先排空任务。</p>
      {resolvedConfig.execution_provenance?.admission_policy === "trust_first" && <p>免审接入：{resolvedConfig.enabled ? "执行已启用" : "执行未启用"}；科学验收：{({ pending: "异步待验收", queued: "异步排队中", running: "异步执行中", passed: "已通过", failed: "失败，停止新派发" })[resolvedConfig.execution_provenance?.scientific_audit_state || resolvedConfig.execution_provenance?.member_audit_state] || "异步待验收"}。重启、取消和断线等完整运行验收单独记录。</p>}
    </section>
    <section className="detail-section machine-policy-section"><header><div><h2>运行时段</h2><span>{draft.unrestricted ? "不限制" : draft.timezone}</span></div><Clock3 size={17} /></header><ScheduleEditor draft={draft} setDraft={setDraft} disabled={!canEdit || saving} /></section>
    <section className="detail-section"><header><div><h2>机器所有者策略</h2><span>模式、资源与空闲门槛</span></div></header><div className="machine-policy-grid"><label>所有者模式<select aria-label="所有者模式" value={draft.owner_mode} disabled={!canEdit || saving} onChange={(event) => setDraft((current) => ({ ...current, owner_mode: event.target.value }))}><option value="open">开放新任务</option><option value="drain">排空，不再接新任务</option><option value="paused">暂停派发</option><option value="emergency_stop">紧急停止</option></select></label>{numericPolicyFields.map(([field, label, unit, min, max]) => <label key={field}>{label}<span><input type="number" min={min} max={limits[field] ?? max} step={field === "non_pool_cpu_max_percent" ? 0.5 : 1} value={draft.values[field]} disabled={!canEdit || saving} onChange={(event) => setDraft((current) => ({ ...current, values: { ...current.values, [field]: Number(event.target.value) } }))} /><small>{unit}</small></span></label>)}</div>{revisionChanged && <p role="status">机器策略已在其他位置变化；当前草稿仍绑定原版本，保存时会核对。</p>}{error && <div className="inline-error">{error}</div>}{notice && <div className="inline-success">{notice}</div>}{canEdit && <div className="settings-actions"><button className="button button-primary" disabled={saving} onClick={save}><Save size={15} />保存机器策略</button>{revisionChanged && <button className="button" disabled={saving} onClick={() => { setEditor(policyEditorState(machine.machine_id, policy, policyRevisionHash)); setError(""); setNotice(""); }}>使用最新策略重新编辑</button>}</div>}</section>
  </>;
}

export function ExecutionTuningEditor({ machine, machineId, config, canEdit, onSaved }) {
  const maxConcurrentUnits = Number(config?.max_concurrent_units ?? 1);
  const [draft, setDraft] = useState(() => executionDraft(config));
  const [profiles, setProfiles] = useState([]);
  const profilesRef = useRef([]);
  const [profileRequest, setProfileRequest] = useState({ status: "loading", error: "" });
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [saving, setSaving] = useState(false);
  const mutation = useMutationGuard();
  const desiredTelemetryHash = config?.telemetry_policy_sha256 || "";
  const appliedTelemetryHash = machine?.applied_telemetry_policy_sha256 || "";
  const telemetrySynced = Boolean(desiredTelemetryHash && desiredTelemetryHash === appliedTelemetryHash);
  const appliedTelemetry = machine?.applied_telemetry_policy;
  const previousConfig = useRef({ id: machineId, value: executionDraft(config) });
  useEffect(() => {
    const before = previousConfig.current;
    const next = executionDraft(config);
    setDraft((current) => before.id !== machineId || JSON.stringify(current) === JSON.stringify(before.value) ? next : current);
    previousConfig.current = { id: machineId, value: next };
  }, [config, machineId]);
  const loadProfiles = useCallback(async () => {
    setProfileRequest((current) => ({ status: profilesRef.current.length ? "refreshing" : "loading", error: current.status === "error" ? "" : current.error }));
    try {
      const value = await api("/v1/profiles");
      profilesRef.current = value;
      setProfiles(value);
      setProfileRequest({ status: "loaded", error: "" });
    } catch (caught) {
      setProfileRequest({ status: "error", error: caught.message });
    }
  }, []);
  useEffect(() => { loadProfiles(); }, [loadProfiles]);
  const profileRows = useMemo(() => profiles.map((profile) => ({
    profile_id: profile.profile_id,
    limit: draft.profile_concurrency_limits[profile.profile_id],
  })), [profiles, draft.profile_concurrency_limits]);
  const setProfileLimit = (profileId, enabled, value = 1) => setDraft((current) => {
    const limits = { ...current.profile_concurrency_limits };
    if (enabled) limits[profileId] = Math.max(1, Math.min(maxConcurrentUnits, Number(value)));
    else delete limits[profileId];
    return { ...current, profile_concurrency_limits: limits };
  });
  const save = () => mutation.run(async () => {
    setSaving(true); setError(""); setNotice("");
    try {
      await api(`/v1/machines/${machineId}/execution-tuning`, { method: "PUT", body: JSON.stringify(draft) });
      setNotice("执行调优已保存");
      await onSaved?.();
    } catch (caught) { setError(caught.message); }
    finally { setSaving(false); }
  });
  return <section className="detail-section execution-tuning-section"><header><div><h2>执行调优</h2><span>保留、轮询与 Profile 并发</span></div></header><div className={`telemetry-sync-state ${telemetrySynced ? "is-synced" : "is-pending"}`} title={telemetrySynced ? "Supervisor 已确认采用网页保存的遥测策略" : "Supervisor 尚未在 heartbeat 中确认采用当前遥测策略"}>{telemetrySynced ? <CheckCircle2 size={16} /> : <RefreshCw size={16} />}<span><strong>{telemetrySynced ? "遥测策略已同步" : "遥测策略等待同步"}</strong><small>{appliedTelemetry ? `实际 ${appliedTelemetry.sample_interval_s}s 采样 · ${appliedTelemetry.cpu_sample_window_s}s 均值 · ${appliedTelemetry.peak_window_s}s 峰值窗口` : "等待 Supervisor 回报实际采样参数"}</small></span></div><div className="machine-policy-grid">
    <label>磁盘预留<span><input type="number" min="1" value={draft.disk_reserve_gib} disabled={!canEdit || saving} onChange={(event) => setDraft({ ...draft, disk_reserve_gib: Number(event.target.value) })} /><small>GiB</small></span></label>
    <label>成功结果保留<span><input type="number" min="0" value={draft.success_retention_days} disabled={!canEdit || saving} onChange={(event) => setDraft({ ...draft, success_retention_days: Number(event.target.value) })} /><small>天</small></span></label>
    <label>失败结果保留<span><input type="number" min="0" value={draft.failure_retention_days} disabled={!canEdit || saving} onChange={(event) => setDraft({ ...draft, failure_retention_days: Number(event.target.value) })} /><small>天</small></span></label>
    <label>状态轮询间隔<span><input type="number" min="5" max="300" value={draft.poll_interval_s} disabled={!canEdit || saving} onChange={(event) => setDraft({ ...draft, poll_interval_s: Number(event.target.value) })} /><small>秒</small></span></label>
  </div><div className="profile-limit-list"><header><strong>Profile 并发上限</strong><span>未单独设置时继承机器有效并发</span><RefreshStatus visible={profileRequest.status === "refreshing"} label="正在刷新 Profile" /></header>
    {profileRequest.status === "loading" && <DataLoadState compact label="正在读取 Profile 并发配置" />}
    {profileRequest.status === "error" && !profileRows.length && <DataLoadState compact error={profileRequest.error} onRetry={loadProfiles} />}
    {profileRows.map(({ profile_id: profileId, limit }) => <div key={profileId}><label className="toggle"><input type="checkbox" checked={limit != null} disabled={!canEdit || saving} onChange={(event) => setProfileLimit(profileId, event.target.checked)} />{profileId}</label><input aria-label={`${profileId} 并发上限`} type="number" min="1" max={maxConcurrentUnits} value={limit ?? 1} disabled={!canEdit || saving || limit == null} onChange={(event) => setProfileLimit(profileId, true, event.target.value)} /></div>)}
    {profileRequest.status === "loaded" && !profileRows.length && <p className="profile-limit-empty">当前没有可配置的 Profile</p>}
    {profileRequest.status === "error" && profileRows.length > 0 && <DataLoadState compact error={`Profile 列表刷新失败：${profileRequest.error}`} onRetry={loadProfiles} />}
  </div>{error && <div className="inline-error">{error}</div>}{notice && <div className="inline-success">{notice}</div>}{canEdit && <div className="settings-actions"><button className="button button-primary" disabled={saving} onClick={save}><Save size={15} />保存执行调优</button></div>}</section>;
}
