import { useMemo } from 'react';

export function selectedProfiles(selected, projectId) {
  return Object.hasOwn(selected, projectId) && Array.isArray(selected[projectId]) ? selected[projectId] : [];
}

// This is an administrator's bounded invitation intent, not a passed acceptance.
export default function MemberAdmissionFields({ projects, profiles, value, onChange, disabled }) {
  const available = useMemo(() => (projects || []).filter(project => project.approved && project.status === 'active'), [projects]);
  const knownProfiles = new Set((profiles || []).filter(profile => !profile.allow_arbitrary_command && profile.platforms?.includes('windows')).map(profile => profile.profile_id));
  const selected = value.project_profiles;
  function choose(projectId, profileId, checked) {
    const next = new Set(selectedProfiles(selected, projectId));
    if (checked) next.add(profileId); else next.delete(profileId);
    const updated = { ...selected };
    if (next.size) updated[projectId] = Array.from(next).sort(); else delete updated[projectId];
    onChange({ ...value, project_profiles: updated });
  }
  const hasTrust = available.some(project => selectedProfiles(selected, project.project_id).length && project.trusted_machine_labels?.length);
  return <fieldset className="member-admission-fields" disabled={disabled}>
    <legend>信任优先自动接活的范围</legend>
    <p>只允许选中的项目和固定执行配置。新邀请在成员明确同意、身份与 runtime/通道就绪后自动接活；科学验收异步进行，失败停止新派发；首次并发为 1。</p>
    {!available.length && <p role="status">没有已批准且有效的项目；请先完成项目登记，不能签发空白的自动计算授权。</p>}
    <div className="member-admission-projects">{available.map(project => <fieldset key={project.project_id}>
      <legend>{project.project_id}</legend>
      {(project.allowed_profiles || []).filter(id => knownProfiles.has(id)).map(id => <label className="member-invitation-option" key={id}>
        <input aria-label={`${project.project_id} / ${id}`} type="checkbox" checked={selectedProfiles(selected, project.project_id).includes(id)}
          onChange={event => choose(project.project_id, id, event.target.checked)} />{id}
      </label>)}
      {project.trusted_machine_labels?.length > 0 && <small>项目当前信任要求：{project.trusted_machine_labels.join('、')}</small>}
    </fieldset>)}</div>
    <div className="member-admission-resources">
      <label>授权 CPU 上限<input aria-label="授权 CPU 上限" type="number" min="1" max="256" value={value.max_cpus} onChange={event => onChange({ ...value, max_cpus: Number(event.target.value) })} /></label>
      <label>授权内存上限（MiB）<input aria-label="授权内存上限（MiB）" type="number" min="256" max="1048576" value={value.max_memory_mb} onChange={event => onChange({ ...value, max_memory_mb: Number(event.target.value) })} /></label>
      <label>计算授权期限<select aria-label="计算授权期限" value={value.valid_for_days === null ? 'unlimited' : 'limited'} onChange={event => onChange({ ...value, valid_for_days: event.target.value === 'unlimited' ? null : 30 })}>
        <option value="unlimited">无到期，直到主动撤销</option><option value="limited">指定天数</option>
      </select></label>
      {value.valid_for_days !== null && <label>计算授权有效期（天）<input aria-label="计算授权有效期（天）" type="number" min="1" max="365" value={value.valid_for_days} onChange={event => onChange({ ...value, valid_for_days: Number(event.target.value) })} /></label>}
    </div>
    {hasTrust && <label className="member-invitation-option"><input type="checkbox" checked={value.acknowledge_project_trust} onChange={event => onChange({ ...value, acknowledge_project_trust: event.target.checked })} />明确授权该成员就绪后参与上述项目的当前信任范围；不授予全局可信机器标签。</label>}
  </fieldset>;
}

export function conditionalInvitation(value, projects, profiles) {
  const entries = Object.entries(value.project_profiles || {});
  if (!entries.length || entries.length > 16) throw new Error('explicit-project-scope-required');
  const known = new Set((profiles || []).filter(profile => !profile.allow_arbitrary_command && profile.platforms?.includes('windows')).map(profile => profile.profile_id));
  const selected = Object.fromEntries(entries.sort(([a], [b]) => a.localeCompare(b)).map(([id, ids]) => {
    const project = (projects || []).find(item => item.project_id === id && item.approved && item.status === 'active');
    if (!project || !Array.isArray(ids) || !ids.length || ids.length > 16 || ids.some(id => !known.has(id) || !project.allowed_profiles.includes(id))
      || (project.trusted_machine_labels?.length && value.acknowledge_project_trust !== true)) throw new Error('invalid-project-scope');
    return [id, Array.from(new Set(ids)).sort()];
  }));
  for (const [field, min, max] of [['max_cpus', 1, 256], ['max_memory_mb', 256, 1048576], ['valid_for_days', 1, 365]]) {
    if (field === 'valid_for_days' && value[field] === null) continue;
    if (!Number.isInteger(value[field]) || value[field] < min || value[field] > max) throw new Error('invalid-admission-limit');
  }
  return { project_profiles: selected, max_cpus: value.max_cpus, max_memory_mb: value.max_memory_mb,
    max_concurrent_units: 1, valid_for_days: value.valid_for_days, acknowledge_project_trust: value.acknowledge_project_trust === true };
}
