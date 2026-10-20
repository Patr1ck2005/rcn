import { useEffect, useMemo, useRef, useState } from "react";
import { usePageRefresh } from "./usePageRefresh";
import { Activity, ArrowLeft, Boxes, ChevronDown, ChevronUp, Clock3, Database, FileCheck2, FlaskConical, GitBranch, Server } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { api } from "./api";
import { DataLoadState, RefreshStatus } from "./AsyncState";
import { attemptSegments, formatDuration, jobCompletionSeries, jobTimeWindow, statusLabel, unitIsReconciling, unitItemCount } from "./format";
import { jobEta, jobPhaseLabel, jobStatusPresentation, reconciliationNotice } from "./jobActivity";
import { AttemptTimeline, CompletionCurve } from "./ProgressCurve";
import { HelpLink } from "./HelpSystem";
import AbandonAttemptControl from "./AbandonAttemptControl";

const time = (value) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "-";
const shortHash = (value) => value ? `${value.slice(0, 12)}...${value.slice(-8)}` : "-";
const coordinateText = (item) => Object.entries(item?.coordinates || {}).map(([key, value]) => `${key}=${value}`).join(" · ") || "无坐标摘要";
const durationText = (value) => Number.isFinite(value) ? `${value.toFixed(value < 10 ? 2 : 1)} s` : "-";

const ATOM_STRIP_LIMIT = 32;
const PROVENANCE_LIMIT = 5;
const EVENT_LIMIT = 100;

function ExpandToggle({ expanded, count, onToggle, noun }) {
  return <button className="expand-toggle" onClick={onToggle}>
    {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
    {expanded ? "收起" : `展开全部 ${count} ${noun}`}
  </button>;
}

function ManifestEvidence({ manifest }) {
  const [expanded, setExpanded] = useState(false);
  const solverCounts = (manifest.item_provenance || []).reduce((counts, item) => {
    counts[item.solver_variant] = (counts[item.solver_variant] || 0) + 1;
    return counts;
  }, {});
  const solverSummary = Object.entries(solverCounts).map(([solver, count]) => `${solver} ${count}`).join(" / ");
  const provenance = manifest.item_provenance || [];
  const shownProvenance = expanded ? provenance : provenance.slice(0, PROVENANCE_LIMIT);
  return <div className="manifest-block">
    <header><Database size={15} /><b>回收 manifest</b><span>{manifest.output_schema} · {manifest.producer?.machine_id || "-"} · {solverSummary || manifest.producer?.solver_variant || "-"}</span></header>
    <div className="manifest-files">{manifest.files.map((file) => <div key={file.relative_path}><code>{file.relative_path}</code><span>{file.size_bytes.toLocaleString("zh-CN")} bytes</span><code title={file.sha256}>SHA-256 {file.sha256}</code></div>)}</div>
    {!!provenance.length && <div className="item-provenance">
      <div className="item-provenance-head"><span>全局 ordinal</span><span>原子项</span><span>实际 solver</span><span>耗时</span></div>
      {shownProvenance.map((item) => <div key={item.item_id}><b>{item.ordinal + 1}</b><code title={item.item_id}>{item.item_id}</code><span className={`solver-${item.solver_variant}`}>{item.solver_variant}</span><time>{durationText(item.duration_s)}</time></div>)}
      {provenance.length > PROVENANCE_LIMIT && <ExpandToggle expanded={expanded} count={provenance.length} noun="行" onToggle={() => setExpanded((value) => !value)} />}
    </div>}
  </div>;
}

export default function JobDetail({ admin = false }) {
  const { jobId } = useParams();
  const currentJobId = useRef(jobId);
  currentJobId.current = jobId;
  const [shell, setShell] = useState(null);
  const [fullJob, setFullJob] = useState(null);
  const [payloadError, setPayloadError] = useState("");
  const [manifests, setManifests] = useState([]);
  const [receipt, setReceipt] = useState(null);
  const [events, setEvents] = useState([]);
  const [error, setError] = useState("");
  const [supplementaryLoading, setSupplementaryLoading] = useState(false);
  const [showAllEvents, setShowAllEvents] = useState(false);
  const payloadAttempted = useRef(null);
  const [requestStates, setRequestStates] = useState({});
  const load = usePageRefresh(async ({ signal, isCurrent }) => {
    const id = jobId;
    setSupplementaryLoading(true);
    const read = async (key, path, commit) => {
      try {
        const value = await api(path, { signal });
        if (!isCurrent()) return;
        commit(value);
        setRequestStates((current) => ({ ...current, [key]: { updatedAt: new Date().toISOString(), error: "" } }));
        if (key === "state") setError("");
        if (key === "payload") setPayloadError("");
      } catch (caught) {
        if (!isCurrent()) return;
        setRequestStates((current) => ({ ...current, [key]: { ...current[key], error: caught.message } }));
        if (key === "state") setError(caught.message);
        if (key === "payload") setPayloadError(caught.message);
      }
    };
    // Paint the operational shell first; each attachment then commits independently.
    await read("state", `/v1/jobs/${id}?view=operational`, setShell);
    if (!isCurrent()) return;
    const reads = [
      read("manifests", `/v1/jobs/${id}/artifact-manifests`, setManifests),
      read("receipt", `/v1/jobs/${id}/origin-import-receipt`, setReceipt),
      read("events", `/v1/jobs/${id}/events`, setEvents),
    ];
    if (payloadAttempted.current !== id) {
      payloadAttempted.current = id;
      reads.push(read("payload", `/v1/jobs/${id}?view=full`, setFullJob));
    }
    await Promise.allSettled(reads);
    if (isCurrent()) setSupplementaryLoading(false);
  }, { key: jobId, initial: true, intervalMs: 15000, resources: ["job-detail", "jobs"] });
  useEffect(() => {
    setShell(null); setFullJob(null); setShowAllEvents(false); setManifests([]); setReceipt(null); setEvents([]);
    setPayloadError(""); setError(""); setRequestStates({});
  }, [jobId]);
  const attachmentErrors = Object.entries(requestStates).filter(([key, state]) => !["state", "payload"].includes(key) && state.error)
    .map(([key, state]) => `${key}：${state.error}${state.updatedAt ? `（保留 ${time(state.updatedAt)} 的内容）` : ""}`).join("；");
  // Scientific payload is immutable; refresh the operational projection only.
  const job = fullJob?.job_id === jobId && shell?.job_id === jobId ? { ...fullJob, ...shell, work_units: shell.work_units.map((unit) => ({
    ...unit, payload: fullJob.work_units.find((item) => item.work_unit_id === unit.work_unit_id)?.payload || unit.payload,
  })) } : shell?.job_id === jobId ? shell : null;
  const payloadReady = Boolean(fullJob);
  const coverage = useMemo(() => {
    const ids = (job?.work_units || []).flatMap((unit) => unit.atomic_item_ids || []);
    const projected = (job?.work_units || []).reduce(
      (total, unit) => total + unitItemCount(unit),
      0,
    );
    return { total: projected, unique: ids.length ? new Set(ids).size : projected };
  }, [job]);
  if (!job && error) return <main className="app-page"><DataLoadState label="正在读取 Job" error={error} onRetry={load} /></main>;
  if (!job) return <main className="app-page"><DataLoadState label="正在读取 Job" /></main>;
  const coverageOk = coverage.total === coverage.unique && coverage.total === job.atomic_item_count;
  const firstAtom = job.work_units?.[0]?.payload?.items?.[0];
  const study = firstAtom?.payload?.study;
  const outputRequest = firstAtom?.payload?.output_request;
  const visibleEvents = showAllEvents ? events : events.slice(0, EVENT_LIMIT);
  const detailWindow = jobTimeWindow(job);
  const timing = jobEta(job);
  return <main className="app-page"><div className="detail-title"><Link className="icon-button" title="返回任务" to="/app/runs"><ArrowLeft size={18} /></Link><div><span>JOB / PROVENANCE</span><h1>{job.job_id}</h1><p>{job.project_id} · {job.user_id} · {jobStatusPresentation(job).text || statusLabel(job.status)}</p></div><HelpLink topic="lifecycle" /><RefreshStatus visible={supplementaryLoading} label="正在加载审计附件" /><div className="detail-capacity"><small>原子项 / WorkUnit</small><strong>{job.atomic_item_count || "-"} / {job.work_units.length}</strong></div></div>
    {error && <section className="job-warning-band"><b>运行状态刷新失败</b><span>{error}。保留最近成功读取 {time(requestStates.state?.updatedAt)} 的状态。</span><button className="button small" onClick={load}>重试读取</button></section>}
    {!payloadReady && <section className="job-warning-band payload-pending"><b>科学载荷后台加载中</b><span>调度状态已就绪；Study、输出契约与原子项明细将随后填充。</span></section>}
    {payloadError && <section className="job-warning-band"><b>科学载荷加载失败</b><span>{payloadError}。调度与审计部分不受影响。</span><button className="button small" onClick={() => { payloadAttempted.current = null; void load(); }}>重试科学载荷</button></section>}
    {attachmentErrors && <section className="job-warning-band"><b>部分审计附件刷新失败</b><span>{attachmentErrors}</span></section>}
    <section className="job-runtime-summary"><article><Activity size={17} /><span><small>当前阶段</small><b>{jobPhaseLabel(job)}</b></span></article><article><Clock3 size={17} /><span><small>总耗时 / 阶段耗时</small><b>{formatDuration(job.total_elapsed_seconds)} / {formatDuration(job.phase_elapsed_seconds)}</b></span></article><article><Clock3 size={17} /><span><small>预计剩余</small><b>{timing.label}</b></span></article><article><Clock3 size={17} /><span><small>预计完成 / 更新时间</small><b>{timing.at ? time(timing.at) : "暂无可靠估计"}{timing.seconds != null && <> · {time(job.eta_updated_at)}</>}</b></span></article></section>
    {reconciliationNotice(job) && <section className="job-warning-band"><b>执行状态待核对</b><span>{reconciliationNotice(job)}</span></section>}
    <section className="detail-section"><header><div><h2>完成轨迹</h2><span>由每个单元的真实完成时间戳推导的累计爬升曲线（0 → 100%）</span></div></header><CompletionCurve series={jobCompletionSeries(job)} /></section>
    {!!job.blocking_reasons?.length && <section className="job-warning-band"><b>当前阻塞</b>{job.blocking_reasons.map((reason) => <span key={reason}>{reason}</span>)}</section>}
    {!!job.failure_reasons?.length && <section className="job-warning-band"><b>Unit 失败证据</b><span>{job.failed_unit_count || 1} 个 Unit 已失败；其余可执行 Unit 继续调度。</span>{job.failure_reasons.map((reason) => <span key={reason}>{reason}</span>)}</section>}
    <section className="job-provenance job-access-summary"><article><GitBranch size={17} /><span><small>来源适配器 / 提交者</small><b>{job.origin_adapter_id || "legacy"} · {job.origin_submitter_id}</b></span></article><article><Boxes size={17} /><span><small>项目 / Profile</small><b>{job.project_id} · {job.execution_profile_id}</b></span></article><article><Activity size={17} /><span><small>请求 / 实际 / 上限 priority</small><b>{job.priority ?? 0} / {job.effective_priority ?? job.priority ?? 0} / {job.priority_ceiling_snapshot ?? "-"}</b></span></article></section>
    <section className="job-provenance campaign-provenance"><article><GitBranch size={17} /><span><small>Campaign / 任务</small><b>{job.campaign_id ? `${job.campaign_id} / ${job.campaign_task_id}` : "v1 单 Job"}</b></span></article><article><FlaskConical size={17} /><span><small>Recipe / Profile</small><b>{job.recipe_kind || "legacy scan"} · {job.execution_profile_id}</b></span></article><article><FlaskConical size={17} /><span><small>Study</small><b>{payloadReady ? (job.study_kind || study?.kind || "旧契约") : "载荷加载中"} · {payloadReady ? (study?.tag || "-") : "-"}</b></span></article><article><FileCheck2 size={17} /><span><small>模板角色 / SHA-256</small><b title={job.template_sha256}>{job.template_role || (payloadReady ? firstAtom?.payload?.template_role : undefined) || "-"} · {shortHash(job.template_sha256)}</b></span></article><article><FileCheck2 size={17} /><span><small>输出契约</small><b title={job.output_contract_sha256}>{shortHash(job.output_contract_sha256)}</b></span></article><article><FileCheck2 size={17} /><span><small>来源 Spec SHA-256</small><b title={job.source_spec_sha256}>{shortHash(job.source_spec_sha256)}</b></span></article><article><Boxes size={17} /><span><small>PartitionPlan</small><b>{job.partition_plan_id || "v1 pre-grouped"}</b></span></article><article className={coverageOk ? "coverage-ok" : "coverage-bad"}><Server size={17} /><span><small>原子项覆盖</small><b>{payloadReady ? `${coverage.unique} 唯一 / ${job.atomic_item_count || coverage.total} 应有` : "载荷加载中"}</b></span></article><article><Database size={17} /><span><small>预计原始输出</small><b>{Number.isFinite(job.estimated_output_bytes) ? `${(job.estimated_output_bytes / 1024 / 1024).toFixed(1)} MiB` : "旧契约未估算"}</b></span></article><article><Database size={17} /><span><small>Origin import</small><b>{receipt ? `${receipt.dataset_id} · ${time(receipt.imported_at)}` : "尚未 import"}</b></span></article></section>
    {!!job.planning_warnings?.length && <section className="job-warning-band"><b>计划警告</b>{job.planning_warnings.map((warning) => <span key={warning}>{warning}</span>)}</section>}
    {outputRequest && <section className="detail-section raw-output-contract"><header><div><h2>原始仿真输出请求</h2><span>Network 只执行、回收和校验，不作物理分析</span></div><code>{outputRequest.solution_archive} / {outputRequest.archive_granularity}</code></header><div className="raw-output-grid"><article><b>Global / Table</b><span>{outputRequest.expressions?.length || 0}</span>{(outputRequest.expressions || []).map((entry) => <code key={entry.name} title={entry.expression}>{entry.name} · {entry.evaluation}</code>)}</article><article><b>结构化场</b><span>{outputRequest.fields?.length || 0}</span>{(outputRequest.fields || []).map((entry) => <code key={entry.name} title={entry.expressions?.join("\n")}>{entry.name} · {entry.grid?.mode || "native"}</code>)}</article><article><b>语义别名</b><span>{outputRequest.semantic_outputs?.length || 0}</span>{(outputRequest.semantic_outputs || []).map((entry) => <code key={entry}>{entry}</code>)}</article></div></section>}
    <section className="detail-section"><header><div><h2>WorkUnit 与 attempt</h2><span>setup、全局 ordinal、机器、solver、runtime、approval、资源、回收和失败 provenance</span></div></header><div className="unit-detail-list">{job.work_units.map((unit) => { const manifest = manifests.find((item) => item.work_unit_id === unit.work_unit_id); const atoms = unit.payload?.items || []; const atomIds = unit.atomic_item_ids || []; const setup = atoms[0]?.setup_fingerprint; const shownAtoms = atomIds.slice(0, ATOM_STRIP_LIMIT); return <article key={unit.work_unit_id}><header><div><b>U{unit.ordinal + 1} · {unit.work_unit_id}</b><small>{unitItemCount(unit)} 原子项 · {statusLabel(unitIsReconciling(unit) ? "reconcile_pending" : unit.activity_state || unit.status)}</small></div><span>{unit.assigned_machine_id || "共享池"}</span></header><AbandonAttemptControl admin={admin} jobId={job.job_id} unit={unit} onCompleted={async () => { const next = await api(`/v1/jobs/${jobId}?view=operational`); if (currentJobId.current === jobId) setShell(next); }} />{setup && <div className="setup-summary"><span>setup</span><code title={setup}>{shortHash(setup)}</code><small>{coordinateText(atoms[0])}{atoms.length > 1 ? ` → ${coordinateText(atoms[atoms.length - 1])}` : ""}</small></div>}<div className="atom-strip">{shownAtoms.map((id, index) => { const atom = atoms[index]; return <i key={id} title={`${id}\n${coordinateText(atom)}`}>{Number.isInteger(atom?.ordinal) ? atom.ordinal + 1 : index + 1}</i>; })}{atomIds.length > ATOM_STRIP_LIMIT && <i className="atom-more" title={`其余 ${atomIds.length - ATOM_STRIP_LIMIT} 个原子项见回收 manifest 明细`}>+{atomIds.length - ATOM_STRIP_LIMIT}</i>}{payloadReady && !atomIds.length && !atoms.length && <span className="atom-empty">该单元无原子项明细（旧契约或空单元）</span>}</div>{detailWindow && <AttemptTimeline segments={attemptSegments(unit)} window={detailWindow} />}<div className="attempt-cards">{(unit.attempts || []).map((attempt) => { const resolved = attempt.resolved_resources?.resources; return <section key={attempt.attempt_id}><header><code>{attempt.attempt_id}</code><span>{statusLabel(attempt.state)}</span></header><dl><div><dt>机器 / solver</dt><dd>{attempt.machine_id || "-"} · {attempt.solver_variant}</dd></div><div><dt>runtime</dt><dd title={attempt.runtime_version}>{shortHash(attempt.runtime_version)}</dd></div><div><dt>approval / fingerprint</dt><dd title={`${attempt.solver_approval_id || "-"}\n${attempt.solver_compatibility_fingerprint || "-"}`}>{attempt.solver_approval_id || "-"} · {shortHash(attempt.solver_compatibility_fingerprint)}</dd></div><div><dt>bundle / external run</dt><dd title={attempt.external_run_id}>{attempt.external_run_id || "尚未跨越远端边界"}</dd></div><div><dt>冻结资源</dt><dd>{resolved ? `${resolved.cpus} CPU · ${resolved.memory_mb} MiB · ${resolved.disk_mb} MiB · ${resolved.gpus} GPU` : "历史记录未固化"}</dd></div><div><dt>派发时压力 / 有效容量</dt><dd>{attempt.pressure_state || "历史记录未固化"} · {attempt.effective_capacity ?? "-"}</dd></div><div><dt>容量原因</dt><dd>{attempt.capacity_reason || "历史记录未固化"}</dd></div><div><dt>开始 / 完成</dt><dd>{time(attempt.started_at)} / {time(attempt.finished_at)}</dd></div><div><dt>迁移 / 失败</dt><dd>{attempt.failure_reason || (attempt.migrated ? "migration" : "无")}</dd></div>{(attempt.state === "abandoned" || attempt.abandonment) && <div><dt>放弃记录</dt><dd>旧结果已弃用；远端停止未得到确认{attempt.abandonment && <> · {time(attempt.abandonment.abandoned_at)} · {attempt.abandonment.reason}</>}</dd></div>}</dl></section>; })}{!unit.attempts?.length && <p>尚无 attempt。</p>}</div>{manifest && <ManifestEvidence manifest={manifest} />}{unit.failure_reason && <div className="unit-failure">{unit.failure_reason}</div>}</article>; })}</div></section>` (line truncated to 2000 chars)
    <section className="detail-section job-event-timeline"><header><div><h2>完整事件时间线</h2><span>{`${events.length} 条与当前 Job、Unit 或 Attempt 绑定的审计事件 · 更新 ${time(requestStates.events?.updatedAt)}`}</span></div></header>{supplementaryLoading && !events.length ? <DataLoadState compact label="正在加载事件时间线" /> : <>{visibleEvents.map((event) => <article key={event.event_id}><time>{time(event.created_at)}</time><b>{event.event_type}</b><code title={event.subject_id}>{event.subject_id}</code><span>{event.details?.reason || event.details?.error || event.actor_id}</span></article>)}{events.length > EVENT_LIMIT && <ExpandToggle expanded={showAllEvents} count={events.length} noun="条事件" onToggle={() => setShowAllEvents((value) => !value)} />}{!events.length && <p>尚无可见事件。</p>}</>}</section>
  </main>;
}
