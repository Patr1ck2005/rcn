import { useEffect, useRef, useState } from 'react';
import { api } from './api';
import MemberAdmissionFields, { conditionalInvitation } from './MemberAdmissionFields.jsx';
import { enrollmentOrigin, invitationDocument, invitationState, pendingKey, pendingMetadata,
  newInvitationOperation, invitationOperationsPath, cancellationReceipt } from './memberInvitationModel.js';
import './memberInvitations.css';

const stamp = value => value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—';

export default function MemberInvitations({ actorId, users = [], enrollments = [], projects = null, profiles = null, admissionReady = false, ready = false, onRefresh }) {
  const key = pendingKey(actorId);
  const [pending, setPending] = useState(() => {
    try { const raw = sessionStorage.getItem(key); return raw ? pendingMetadata(JSON.parse(raw)) : null; }
    catch { return { state: 'storage-unavailable' }; }
  });
  const [draft, setDraft] = useState({ owner_user_id: '', worker: true, ttl_minutes: 60, control_plane_url: '' });
  const [newMember, setNewMember] = useState(false);
  const [displayName, setDisplayName] = useState('');
  const [automatic, setAutomatic] = useState(projects !== null);
  const [admission, setAdmission] = useState({ project_profiles: {}, max_cpus: 4, max_memory_mb: 16384,
    valid_for_days: null, acknowledge_project_trust: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [now, setNow] = useState(Date.now());
  const [hasDownload, setHasDownload] = useState(false);
  const [downloadRequested, setDownloadRequested] = useState(false);
  const secret = useRef(null);
  const issuance = useRef(null);
  const [retryable, setRetryable] = useState(false);
  const locked = useRef(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => { mounted.current = false; secret.current = null; issuance.current = null; clearInterval(timer); };
  }, []);
  const records = enrollments.filter(item => item.registration_mode === 'resumable-v1');
  useEffect(() => {
    const item = secret.current;
    if (!item) return;
    const current = records.find(record => record.enrollment_id === item.enrollment_id);
    if (Date.parse(item.expires_at) <= now || current?.revoked_at || current?.used_at) {
      secret.current = null; issuance.current = null; setHasDownload(false); setRetryable(false);
      setNotice('邀请已过期、撤销或用于登记，页面不再提供该文件。机器准入仍由验收决定。');
    }
  }, [enrollments, now]);

  function persist(value, expectedOperationId = null) {
    if (expectedOperationId) {
      const raw = sessionStorage.getItem(key);
      if (!raw || pendingMetadata(JSON.parse(raw)).operation_id !== expectedOperationId) return false;
    }
    if (value) sessionStorage.setItem(key, JSON.stringify(pendingMetadata(value)));
    else sessionStorage.removeItem(key);
    if (mounted.current) setPending(value ? pendingMetadata(value) : null);
    return true;
  }
  async function refreshRecords() {
    try { await onRefresh?.(); }
    catch { if (mounted.current) setError('邀请记录刷新失败，保留本次交付状态；请刷新核对，不要重复签发。'); }
  }
  async function issue() {
    if (locked.current || pending || !ready || location.protocol !== 'https:') return;
    const owner = users.find(user => user.user_id === draft.owner_user_id && user.active);
    if (!newMember && (!owner || (draft.worker && !owner.roles?.includes('machine_owner')))) return;
    let request;
    try {
      request = { ...draft, control_plane_url: enrollmentOrigin(draft.control_plane_url) };
      if (newMember) {
        if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$/.test(draft.owner_user_id)
          || users.some(user => user.user_id === draft.owner_user_id) || !displayName.trim() || displayName.length > 160) throw new Error();
        request.new_member_display_name = displayName.trim();
      }
      if (automatic && draft.worker) {
        if (!admissionReady) throw new Error();
        request.conditional_admission = conditionalInvitation(admission, projects, profiles);
      }
      if (!Number.isInteger(request.ttl_minutes) || request.ttl_minutes < 1 || request.ttl_minutes > 1440) throw new Error();
    } catch { setError('请核对成员信息、独立 HTTPS 入口和明确的项目授权范围；不能使用重复成员 ID 或空白计算范围。'); return; }
    let next;
    try {
      const existing = sessionStorage.getItem(key);
      if (existing) { setPending(pendingMetadata(JSON.parse(existing))); return; }
      next = newInvitationOperation(request);
      next.marker = { state: 'issuing', operation_id: next.operation_id,
        owner_user_id: request.owner_user_id, started_at: new Date().toISOString() };
      persist(next.marker); // Durable NON-secret identity before the first write.
    } catch { setError('安全随机数或会话存储不可用，尚未签发；不会使用弱随机数或跳过检查点。'); return; }
    issuance.current = next;
    await sendIssuance();
  }
  async function sendIssuance() {
    const next = issuance.current;
    if (locked.current || !next || !ready || location.protocol !== 'https:') return;
    locked.current = true; setBusy(true); setError(''); setNotice(''); setRetryable(false);
    try {
      // Same origin, same operation ID, same frozen delivery material on every retry.
      const response = await api(`${invitationOperationsPath}/${next.operation_id}`, { method: 'PUT',
        body: JSON.stringify(next.request), redirect: 'error', timeoutMs: 15000 });
      const document = invitationDocument(response, next.request);
      if (!persist({ ...next.marker, state: 'awaiting-delivery', enrollment_id: document.enrollment_id }, next.operation_id)) return;
      if (mounted.current) {
        secret.current = document; setHasDownload(true); setDownloadRequested(false);
        setNotice('邀请已确认。下载后仅私下交付给该成员；同次重试不会增加邀请或延长有效期。');
      }
    } catch (caught) {
      const rejected = [400, 401, 403, 409, 415, 422].includes(caught.status);
      if (mounted.current) {
        setRetryable(!rejected && Boolean(issuance.current));
        setError(rejected
          ? '签发被拒绝，请核对身份、角色或邀请状态；保留操作记录，不创建替代邀请。'
          : '签发结果未确认。可重试同一次签发，不会生成第二份邀请；也可取消这次未交付邀请。');
      }
    } finally {
      locked.current = false;
      if (mounted.current) setBusy(false);
      await refreshRecords();
    }
  }
  async function cancelPending() {
    if (locked.current || !pending?.operation_id || location.protocol !== 'https:') return;
    const identity = pending.operation_id;
    locked.current = true; setBusy(true); setError(''); setRetryable(false);
    issuance.current = null; secret.current = null; setHasDownload(false);
    try {
      const result = cancellationReceipt(await api(`${invitationOperationsPath}/${identity}/cancel`, {
        method: 'POST', body: '{}', redirect: 'error', timeoutMs: 15000,
      }), identity);
      if (!persist(null, identity)) return;
      if (mounted.current) setNotice(result.state === 'registered'
        ? '这份邀请已用于设备登记，未撤销登记续接或机器凭据，也未停止计算。'
        : '本次未交付邀请已取消；迟到的签发请求也不能重新激活它。');
    } catch { if (mounted.current) setError('取消结果未确认，仍保留原操作；可重试取消，不能直接清除或另发邀请。'); }
    finally { locked.current = false; if (mounted.current) setBusy(false); await refreshRecords(); }
  }
  function download() {
    if (busy || !secret.current || Date.parse(secret.current.expires_at) <= Date.now()) return;
    const document = secret.current;
    const url = URL.createObjectURL(new Blob([JSON.stringify(document, null, 2) + '\n'], { type: 'application/json' }));
    const link = window.document.createElement('a');
    link.href = url; link.download = `RCN-invitation-${document.machine_id}.json`;
    window.document.body.appendChild(link);
    try { link.click(); setDownloadRequested(true); }
    catch { setError('未能发起文件下载，邀请仍保留在当前页面；请重试下载而不是重新签发。'); }
    finally { link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
  }
  function finishDelivery() {
    if (busy || (hasDownload && !downloadRequested) || (!hasDownload && pending?.operation_id)) return;
    try { if (!persist(null, pending?.operation_id)) return; secret.current = null; issuance.current = null; setRetryable(false); setHasDownload(false); setDownloadRequested(false); setError(''); setNotice('本次交付检查点已关闭。下载文件仍是私密邀请；登记不等于计算准入。'); }
    catch { setError('交付检查点未清除，请保留现场。'); }
  }
  async function revoke(item) {
    if (locked.current || !ready || location.protocol !== 'https:') return;
    locked.current = true; setBusy(true); setError('');
    if (secret.current?.enrollment_id === item.enrollment_id) { secret.current = null; setHasDownload(false); }
    try {
      await api(`/v1/admin/member-invitations/${encodeURIComponent(item.enrollment_id)}/revoke`,
        { method: 'POST', redirect: 'error', timeoutMs: 15000 });
      setNotice('已撤销邀请及登记续接能力；没有撤销已登记机器的凭据，也没有停止计算。');
      if (pending?.enrollment_id === item.enrollment_id) { persist(null, pending.operation_id); issuance.current = null; setRetryable(false); }
    } catch { setError('撤销结果未确认。请刷新核对；再次撤销同一个邀请不会签发新身份。'); }
    finally { locked.current = false; if (mounted.current) setBusy(false); await refreshRecords(); }
  }
  async function revokeCompute(item) {
    if (locked.current || !ready || location.protocol !== 'https:') return;
    locked.current = true; setBusy(true); setError('');
    try {
      await api(`/v1/admin/member-admissions/${encodeURIComponent(item.enrollment_id)}/revoke`, { method: 'POST', body: '{}', redirect: 'error' });
      setNotice('该邀请的计算授权已撤销；阻止后续接活，不停止正在运行的计算，也不删除设备身份。');
    } catch { setError('计算授权撤销结果未确认，请刷新核对同一邀请，不清除记录。'); }
    finally { locked.current = false; if (mounted.current) setBusy(false); await refreshRecords(); }
  }
  const eligible = users.filter(user => user.active && (!draft.worker || user.roles?.includes('machine_owner')));
  let scopeValid = true;
  if (automatic && draft.worker) {
    try { conditionalInvitation(admission, projects, profiles); scopeValid = admissionReady; } catch { scopeValid = false; }
  }
  const identityValid = newMember
    ? /^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$/.test(draft.owner_user_id) && displayName.trim() && !users.some(user => user.user_id === draft.owner_user_id)
    : eligible.some(user => user.user_id === draft.owner_user_id);
  const canIssue = ready && !busy && !pending && location.protocol === 'https:' && identityValid && scopeValid;
  return <section className="detail-section member-invitations" aria-label="新版成员邀请" aria-busy={busy}>
    <header><div><h2>邀请新成员</h2><span>通用安装包 + 私密 v2 邀请；新计算邀请采用信任优先，验收异步补齐。</span></div></header>
    {location.protocol !== 'https:' && <p role="status">当前不是 HTTPS 管理入口，不能签发或撤销新版邀请。不要将管理员令牌发送到未经核验的新地址。</p>}
    {!ready && <p role="status">成员与邀请记录尚未完整加载，请刷新后操作。</p>}
    <form className="member-invitation-form" onSubmit={event => { event.preventDefault(); issue(); }}>
      <label className="member-invitation-option"><input type="checkbox" checked={newMember} disabled={busy || Boolean(pending)} onChange={event => { setNewMember(event.target.checked); setDraft({ ...draft, owner_user_id: '' }); }} />创建新成员并同时邀请</label>
      {newMember ? <><label>新成员 ID<input aria-label="新成员 ID" value={draft.owner_user_id} maxLength={160} disabled={busy || Boolean(pending)} onChange={event => setDraft({ ...draft, owner_user_id: event.target.value })} /></label><label>新成员姓名<input aria-label="新成员姓名" value={displayName} maxLength={160} disabled={busy || Boolean(pending)} onChange={event => setDisplayName(event.target.value)} /></label></> : <label>获邀成员<select aria-label="获邀成员" value={draft.owner_user_id} disabled={busy || Boolean(pending)} onChange={event => setDraft({ ...draft, owner_user_id: event.target.value })}><option value="">选择已有成员</option>{eligible.map(user => <option key={user.user_id} value={user.user_id}>{user.display_name || user.user_id}（{user.user_id}）</option>)}</select></label>}
      <label>独立 HTTPS 接入地址<input aria-label="独立 HTTPS 接入地址" type="url" placeholder="https://enrollment.example" autoComplete="off" value={draft.control_plane_url} disabled={busy || Boolean(pending)} onChange={event => setDraft({ ...draft, control_plane_url: event.target.value })} /></label>
      <label>邀请有效期（分钟）<input aria-label="邀请有效期（分钟）" type="number" min="1" max="1440" value={draft.ttl_minutes} disabled={busy || Boolean(pending)} onChange={event => setDraft({ ...draft, ttl_minutes: Number(event.target.value) })} /></label>
      <label className="member-invitation-option"><input type="checkbox" checked={draft.worker} disabled={busy || Boolean(pending)} onChange={event => setDraft({ ...draft, worker: event.target.checked, owner_user_id: '' })} />申请参与计算（成员需要 machine_owner 角色）</label>
      {draft.worker && projects !== null && <label className="member-invitation-option"><input type="checkbox" checked={automatic} disabled={busy || Boolean(pending)} onChange={event => setAutomatic(event.target.checked)} />成员同意并就绪后自动接活（验收异步）</label>}
      {draft.worker && automatic && <MemberAdmissionFields projects={projects} profiles={profiles} value={admission} onChange={setAdmission} disabled={busy || Boolean(pending) || !admissionReady} />}
      <button type="submit" className="button button-primary" disabled={!canIssue}>签发私密邀请</button>
    </form>
    {error && <p className="inline-error" role="alert">{error}</p>}
    {notice && <p role="status">{notice}</p>}
    {pending && <div className="member-invitation-delivery"><b>{hasDownload ? '待私下交付' : '上次交付需要核对'}</b><p>成员：{pending.owner_user_id || '未知'} · {stamp(pending.started_at)}。页面刷新后不会恢复邀请码，请核对下方记录。不要盲目重新签发。</p>{pending.enrollment_id && <code>{pending.enrollment_id}</code>}
      {hasDownload && <><button className="button button-primary" disabled={busy} onClick={download}>下载私密邀请 JSON</button><button className="button" disabled={busy || !downloadRequested} onClick={finishDelivery}>已私下交付，清除页面凭据</button></>}
      {!hasDownload && pending.operation_id && <><p>取消只作废本次尚未登记的邀请，不停止已登记机器。页面刷新后不能恢复内存中的交付材料，但可以准确取消本次操作。</p>{retryable && <button className="button button-primary" disabled={busy || !ready} onClick={sendIssuance}>重试同一次签发</button>}<button className="button" disabled={busy || location.protocol !== 'https:'} onClick={cancelPending}>取消这次未交付邀请</button></>}
      {!hasDownload && !pending.operation_id && <button className="button" disabled={busy || !ready} onClick={finishDelivery}>已核对并处理未交付邀请，结束本次操作</button>}
    </div>}
    <div className="member-invitation-actions"><button className="button" disabled={busy} onClick={refreshRecords}>刷新邀请记录</button><span>撤销邀请不等于机器退网，不会停止成员计算。</span></div>
    <div className="member-invitation-records">{records.map(item => <article key={item.enrollment_id}><div><b>{item.owner_user_id}</b><span>{invitationState(item, now)}</span><small>{item.enrollment_id}</small><small>邀请有效至 {stamp(item.expires_at)} · 机器 {item.invited_machine_id || item.machine_id || '未确认'}</small>{item.conditional_admission_offer && <small>计算范围：{Object.keys(item.conditional_admission_offer.scope?.project_profiles || {}).join('、')} · {item.member_admission_result?.state === 'revoked' ? '计算授权已撤销' : item.conditional_admission_offer.expires_at === null ? '计算授权无到期，直到主动撤销' : `计算授权有效至 ${stamp(item.conditional_admission_offer.expires_at)}`}</small>}</div>{item.conditional_admission_offer && item.member_admission_result?.state !== 'revoked' && <button className="button small" disabled={busy || location.protocol !== 'https:'} onClick={() => revokeCompute(item)}>撤销计算授权</button>}{!item.revoked_at && <button className="button small" disabled={busy || location.protocol !== 'https:'} onClick={() => revoke(item)}>{item.used_at ? '撤销登记续接' : '撤销未用邀请'}</button>}</article>)}{ready && !records.length && <p>尚无新版邀请记录。</p>}</div>
  </section>;
}
