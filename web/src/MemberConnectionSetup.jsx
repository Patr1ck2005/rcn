import { useEffect, useRef, useState } from "react";
import { BookOpen, CheckCircle2, Copy, Download, KeyRound, RefreshCw, Upload } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "./api";
import { useMutationGuard } from "./useMutationGuard";
import MemberAgentSetup from "./MemberAgentSetup";
import MemberPairing from "./MemberPairing";
import { memberIdentityVerified } from "./memberAgentConfig";
import {
  connectionError, connectionStages, downloadDoctorReport, importComplete, importPreview, importRunning,
  pendingConnectionImport, rememberConnectionImport, safeDiagnosticText, sanitizedDoctorReport, uploadConnectionBundle,
} from "./memberConnectionModel";

const checkNames = { passed: "通过", warning: "注意", failed: "未通过", skipped: "未检查" };
const stageNames = { installation: "本机安装", local_identity: "本机身份", local_config: "本机配置", connection: "中心连接", ssh: "SSH 客户端", login: "个人登录", submission: "提交权限", agent: "Agent 配置", transport: "连接通道", identity: "个人身份" };

function ManualConnection({ session, onSession }) {
  const configured = ["https", "managed-ssh"].includes(session?.configured_connection?.mode) ? session.configured_connection : null;
  const [center, setCenter] = useState(session?.center_url?.startsWith("https://") ? session.center_url : "");
  const [personalToken, setPersonalToken] = useState("");
  const [error, setError] = useState("");
  const mutation = useMutationGuard();
  const submit = (event) => mutation.run(async () => {
    setError("");
    try {
      const connected = await api("/local/v1/session", { method: "POST", body: JSON.stringify({ center_url: configured?.center_reference || center.trim(), token: personalToken.trim() }) });
      onSession(connected);
    } catch (failure) { setError(connectionError(failure)); }
    finally { setPersonalToken(""); }
  }, event);
  return <details className="member-panel member-advanced">
    <summary>高级恢复：使用已有个人登录信息</summary><p>已有个人访问凭据时，可手动登录 HTTPS 中心；新成员请使用上方“加入课题组”。</p>
    <form className="member-manual-form" onSubmit={submit}>{configured
      ? <label>管理员预配置的中心连接<input value="课题组计算中心" readOnly /></label>
      : <label>中心 HTTPS 地址<input type="url" name="center_url" value={center} onChange={(event) => setCenter(event.target.value)} placeholder="https://compute.example.org" pattern="https://.*" required autoComplete="url" /></label>}
      <label>个人访问 token<input type="password" name="personal_token" value={personalToken} onChange={(event) => setPersonalToken(event.target.value)} required autoComplete="off" /></label>
      {error && <div className="form-error" role="alert">{error}</div>}
      <button className="button" disabled={mutation.busy}><KeyRound size={16} />{mutation.busy ? "正在连接…" : "连接并进入"}</button>
    </form>
  </details>;
}

export default function MemberConnectionSetup({ session, onSession, onRetry, error: externalError }) {
  const [record, setRecord] = useState(null);
  const [recoverId, setRecoverId] = useState(pendingConnectionImport);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [doctor, setDoctor] = useState(null);
  const [doctorError, setDoctorError] = useState("");
  const [action, setAction] = useState("");
  const [repairConfirmed, setRepairConfirmed] = useState(false);
  const [importConfirmed, setImportConfirmed] = useState(false);
  const [pairingReady, setPairingReady] = useState(false);
  const mutation = useMutationGuard();
  const doctorMutation = useMutationGuard();
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const applyRecord = async (value) => {
    if (!mounted.current) return;
    setRecord(value); setRecoverId(value.import_id); rememberConnectionImport(importComplete(value) ? null : value.import_id);
    if (importComplete(value)) {
      const connected = value.session || await api("/local/v1/session");
      if (mounted.current) { setDoctor(null); onSession(connected); setNotice("个人连接已导入。现在可以选择 Agent 并一键配置。"); }
    }
  };
  const recover = () => mutation.run(async () => {
    const id = record?.import_id || recoverId; if (!id) return;
    setAction("recover"); setError("");
    try { await applyRecord(await api(`/local/v1/connection-imports/${encodeURIComponent(id)}`)); }
    catch (failure) { setError(`${connectionError(failure)} 原导入编号已保留，请恢复同一导入。`); }
    finally { setAction(""); }
  });
  // Read an existing operation on return; never replay a confirmation automatically.
  useEffect(() => { if (recoverId && !record) void recover(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!importRunning(record) || mutation.busy) return;
    const timer = setTimeout(() => { void recover(); }, 1800);
    return () => clearTimeout(timer);
  }, [record, mutation.busy]); // eslint-disable-line react-hooks/exhaustive-deps
  const importFile = (event) => {
    const input = event.target; const file = input.files?.[0]; if (!file) return;
    void mutation.run(async () => {
      setAction("upload"); setError(""); setNotice(""); setImportConfirmed(false);
      try { await applyRecord(await uploadConnectionBundle(file)); }
      catch (failure) { setError(connectionError(failure)); }
      finally { setAction(""); input.value = ""; }
    }, event);
  };
  const confirm = () => mutation.run(async () => {
    if (!record?.import_id || !importConfirmed) return;
    const id = record.import_id;
    setAction("confirm"); setError(""); setNotice(""); rememberConnectionImport(id);
    setRecord((previous) => ({ ...previous, state: "importing" }));
    try { await applyRecord(await api(`/local/v1/connection-imports/${encodeURIComponent(id)}/confirm`, { method: "POST", body: "{}" })); }
    catch (failure) {
      try { await applyRecord(await api(`/local/v1/connection-imports/${encodeURIComponent(id)}`)); setError(connectionError(failure)); }
      catch { setRecord((previous) => ({ ...previous, state: "unknown" })); setError(`${connectionError(failure)} 原导入编号已保留，请恢复同一导入；不要重新导入。`); }
    } finally { setAction(""); }
  });
  const runDoctor = (repair = false) => doctorMutation.run(async () => {
    setDoctorError(""); setNotice("");
    try {
      const result = await api("/local/v1/doctor", { method: "POST", body: JSON.stringify({ repair }) });
      if (!Array.isArray(result?.checks)) throw new Error("连接自检响应格式不完整，请恢复本机服务后重试。");
      if (!mounted.current) return;
      setDoctor(sanitizedDoctorReport(result)); setRepairConfirmed(false);
      // A doctor is click-triggered. Reuse its report rather than running it again for export.
      try { const verified = await api("/local/v1/session"); if (mounted.current) onSession(verified); } catch { /* Preserve the diagnostic evidence even if the session cannot be read. */ }
    } catch (failure) { if (mounted.current) setDoctorError(connectionError(failure)); }
  });
  const copyReport = async () => {
    try { await navigator.clipboard.writeText(JSON.stringify(sanitizedDoctorReport(doctor), null, 2)); setNotice("已复制脱敏诊断报告，可交给本机 Agent 排查。"); }
    catch { setDoctorError("复制未完成，请下载诊断 JSON 后交给 Agent。"); }
  };
  const online = memberIdentityVerified(session);
  const canRepair = doctor?.checks?.some((check) => ["member_openssh_missing", "member_connection_unavailable"].includes(check.reason_code));
  const currentPreview = record?.preview;
  const canReplace = !mutation.busy && !importRunning(record) && !["unknown", "recovery_required"].includes(record?.state);
  return <main className="app-page member-page member-setup"><div className="page-title"><div><span>MEMBER / SETUP</span><h1>连接与 Agent 配置</h1><p>{session?.connected ? "管理当前个人连接与 Agent，或运行自检恢复连接。" : "填写姓名与设备，申请加入课题组，批准后自动连接。"}</p></div><Link className="button" to="/app/help"><BookOpen size={16} />帮助与文档</Link></div>
    {!session?.connected && <ol className="member-steps member-setup-steps" aria-label="成员接入流程"><li className="current">申请加入</li><li>管理员核对与批准</li><li>自动连接与配置 Agent</li></ol>}
    <MemberPairing session={session} onSession={onSession} onReadyChange={setPairingReady} />
    <details className="member-panel member-advanced" open={Boolean(record || recoverId) || undefined}><summary>高级恢复：导入已有个人连接包</summary>
    <section><header><h2><KeyRound size={18} /> 导入个人连接包</h2><span className="member-badge">{online ? "个人身份已连接" : "等待个人连接"}</span></header>
      <p>组内受管 SSH 与 HTTPS 连接均从同一入口接入。连接包仅供你本人使用，由本机客户端安全保存；无需另行复制 Agent token。</p>
      <div className="member-actions"><label className={`button button-primary member-file-button${canReplace ? "" : " disabled"}`}><Upload size={16} />{action === "upload" ? "正在校验连接包…" : "选择私密连接包"}<input aria-label="选择私密连接包" type="file" accept=".zip,.rcn,application/zip" onChange={importFile} disabled={!canReplace} /></label>
        {recoverId && <button className="button" disabled={mutation.busy} onClick={recover}><RefreshCw size={16} />{action === "recover" ? "正在读取原导入…" : "恢复同一导入"}</button>}
        <Link to="/app/help/member-getting-started">连接包与接入说明</Link></div>
      {record && <div className="member-import-status" aria-live="polite"><h3>{connectionStages[record.state] || safeDiagnosticText(record.state, 80)}</h3>
        <p>原导入编号：<code>{record.import_id}</code></p>
        {currentPreview && <dl className="member-metadata"><div><dt>连接包成员</dt><dd>{safeDiagnosticText(currentPreview.owner_user_id, 100) || "由中心核验"}</dd></div><div><dt>计算中心</dt><dd>{safeDiagnosticText(currentPreview.center_name, 160) || "课题组计算中心"}</dd></div><div><dt>连接方式</dt><dd>{currentPreview.mode === "managed-ssh" ? "组内受管 SSH" : currentPreview.mode === "https" ? "HTTPS" : "由连接包指定"}</dd></div></dl>}
        {Array.isArray(record.stages) && <ol className="member-checks" aria-label="导入阶段">{record.stages.map((stage, index) => <li key={index}><b>{safeDiagnosticText(stage.stage || stage.name, 100)}</b><span>{checkNames[stage.status] || safeDiagnosticText(stage.status, 80)}</span><p>{safeDiagnosticText(stage.message)}</p></li>)}</ol>}
        {record.error && <p role="alert">{connectionError(typeof record.error === "string" ? { message: record.error } : record.error)}</p>}
        {record.reason_code && <p role="alert">{connectionError({ reason_code: record.reason_code })}</p>}
        {record.state === "recovery_required" && <p>请保留原导入与本机任务记录，运行下方自检并将脱敏报告交给 Agent 或管理员。</p>}
        {(importPreview(record) || record.state === "failed" || (importRunning(record) && action !== "confirm")) && <><label className="member-consent"><input type="checkbox" checked={importConfirmed} disabled={mutation.busy} onChange={(event) => setImportConfirmed(event.target.checked)} /><span>我确认连接包属于本人，并将使用上方中心与身份。</span></label><button className="button button-primary" disabled={mutation.busy || !importConfirmed} onClick={confirm}>{record.state === "failed" ? "按原编号重试导入" : importRunning(record) ? "继续原导入" : "确认并接入中心"}</button></>}
        {importRunning(record) && <p role="status">正在执行原导入，请稍候；关闭页面后仍可按原编号恢复。</p>}
      </div>}
      {(error || externalError) && <div className="form-error" role="alert">{error || externalError}</div>}
      {externalError && <button className="button small" onClick={onRetry}>恢复本机连接</button>}
    </section></details>
    <details className="member-connection-management" open={!pairingReady || undefined}><summary>连接自检与更多 Agent 配置</summary>
    <section className="member-panel"><header><h2><CheckCircle2 size={18} /> 连接自检与恢复</h2><span>未登录、离线或配置损坏时均可使用</span></header><p>点击后检查本机配置、连接通道和个人身份。报告仅保留脱敏检查结果，可直接交给 Agent。</p>
      <div className="member-actions"><button className="button" disabled={doctorMutation.busy || mutation.busy} onClick={() => runDoctor(false)}><RefreshCw size={16} />{doctorMutation.busy ? "正在自检…" : "重新自检"}</button>
        {doctor && <><button className="button" onClick={copyReport}><Copy size={16} />复制诊断给 Agent</button><button className="button" onClick={() => downloadDoctorReport(doctor)}><Download size={16} />下载诊断 JSON</button></>}</div>
      {doctor && <div className="member-doctor-result" aria-live="polite"><h3>{doctor.ok ? "自检通过" : "请处理以下检查项"}</h3><p>{doctor.summary}</p><p>诊断编号：<code>{doctor.diagnostic_id || "未提供"}</code></p>
        {doctor.observed_at && <p>检查时间：{doctor.observed_at}</p>}
        <ol className="member-checks" aria-label="连接检查结果">{doctor.checks.map((check, index) => <li className={`member-check-${check.status}`} key={`${check.stage}-${index}`}><b>{stageNames[check.stage] || check.stage}</b><span>{checkNames[check.status]}</span><p>{check.message}</p>{check.reason_code && <code>{check.reason_code}</code>}{check.next_action && <p>下一步：{check.next_action}</p>}{check.help_slug && <Link to={`/app/help/${check.help_slug}`}>查看此项帮助</Link>}</li>)}</ol>
        {doctor.next_actions.length > 0 && <><h3>本次建议</h3><ul>{doctor.next_actions.map((item, index) => <li key={index}>{item}</li>)}</ul>{!doctor.ok && canRepair && <><p>此操作仅恢复已登记的本机连接或补齐缺失的 SSH 客户端组件。</p><label className="member-consent"><input type="checkbox" checked={repairConfirmed} disabled={doctorMutation.busy} onChange={(event) => setRepairConfirmed(event.target.checked)} /><span>按本次自检建议执行允许的本机安全修复。</span></label><button className="button" disabled={doctorMutation.busy || !repairConfirmed} onClick={() => runDoctor(true)}>执行建议的本机安全修复</button></>}</>}
      </div>}
      {doctorError && <div className="form-error" role="alert">{doctorError}</div>}
    </section>
    {session?.connected && <MemberAgentSetup session={session} onSession={onSession} doctor={doctor} onCheck={() => runDoctor(false)} checking={doctorMutation.busy} embedded />}
    </details>
    {!session?.connected && <ManualConnection session={session} onSession={(value) => { setDoctor(null); onSession(value); }} />}
    {notice && <p className="member-notice" role="status">{notice}</p>}
    {session?.connected && !pairingReady && <div className="member-actions"><Link className="button" to="/app/submit">继续提交任务</Link><Link className="button" to="/app/contribution">可选：贡献我的电脑</Link></div>}
  </main>;
}
