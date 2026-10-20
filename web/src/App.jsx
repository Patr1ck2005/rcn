import { lazy, memo, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, AlertTriangle, ArchiveRestore, ArrowDown, ArrowLeft, ArrowLeftRight, ArrowRight, BookOpen,
  Boxes, CheckCircle2, ChevronDown, ChevronRight, ChevronUp, CircleHelp, Clock3, Cpu, Database, Filter,
  Gauge, GitCompareArrows, KeyRound, LogOut, Menu, MemoryStick, MonitorCog, Network, PanelRightOpen,
  RefreshCw, Search, Server, ShieldCheck, SlidersHorizontal, TerminalSquare, Users, Workflow, X,
} from "lucide-react";
import {
  BrowserRouter, Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate, useSearchParams,
} from "react-router-dom";

import { api, connectStateStream, detectMemberClient, setToken, token } from "./api";
import { capacityDisplay, formatAge, formatDuration, gpuDisplay, jobCompletionSeries, jobMachineDurations, jobProgressTotals, jobTimeWindow, attemptSegments, unitEtaLabel, unitItemCount, unitIsReconciling, unitReassignable } from "./format";
import { currentJobPhase, jobEnvironmentLabel, jobEta, jobPhaseLabel, jobStatusPresentation, reconciliationNotice } from "./jobActivity";
import { AttemptTimeline, CompletionCurve, MiniSpark } from "./ProgressCurve";
import { MachineControlDialog } from "./ControlDialogs";
import { HelpCenter, HelpLink, HelpProvider, rememberHelpReturn } from "./HelpSystem";
import { DataLoadState, RefreshStatus } from "./AsyncState";
import { createRefreshCoalescer, createStartupBaseline } from "./liveRefresh";
import { applyJobsListing, jobsLoadRangeText, loadJobsListing } from "./jobsListing";
import { notifyDataRefresh, watchPageReturn } from "./freshness";
import { usePageRefresh } from "./usePageRefresh";
import { useMutationGuard } from "./useMutationGuard";
import { useJobTransactions } from "./useJobTransactions";
import { usePressureOverride } from "./usePressureOverride";
import { eventAffectsRoute, eventResources, routeResources } from "./routeReads";
import { fleetRecords, isHistorical } from "./fleetRecords";
import FleetHistory, { FleetGroupSummary } from "./FleetHistory";
import AbandonAttemptControl from "./AbandonAttemptControl";
import JobExecutionConditions from "./JobExecutionConditions";
import MetadataRecovery from "./MetadataRecovery";

const MachineDetail = lazy(() => import("./MachineDetail"));
const FleetCompare = lazy(() => import("./FleetCompare"));
const ControlCenter = lazy(() => import("./ControlCenter"));
const AdminConsole = lazy(() => import("./AdminConsole"));
const AlertCenter = lazy(() => import("./AlertCenter"));
const JobDetail = lazy(() => import("./JobDetail"));
const ControlOperationDetail = lazy(() => import("./ControlOperationDetail"));
const Projects = lazy(() => import("./Projects"));
const ClusterInsights = lazy(() => import("./ClusterInsights"));
const MemberClient = lazy(() => import("./MemberClient"));

const labels = {
  open: "开放", drain: "排空", paused: "暂停", emergency_stop: "紧急停止",
  queued: "排队", prepared: "已预备", assigned: "已派发", running: "运行中", finalizing: "导出终结中", collecting: "回收中",
  completed: "完成", cancelled: "已取消", failed_retriable: "待自动重试",
  failed_terminal: "终止失败", online: "在线", offline: "离线", live: "实时",
  retry: "待重试",
  stale: "过期", pending: "待处理", warning: "警告", passed: "通过",
  enabled: "启用", disabled: "禁用", active: "活动", standby: "备用", stopped: "已停止",
  awaiting_approval: "等待审批", awaiting_environment: "等待环境", blocked: "受阻",
  cancel_pending: "取消中", reconcile_pending: "等待对账", unknown: "未知",
};
const label = (value) => labels[value] || value || "未知";
const statusHints = {
  awaiting_approval: "请求已通过科学合同校验，正在等待当前 sealed runtime 的兼容 solver approval。",
  awaiting_environment: "审批条件已满足，但 runtime、执行器、容量或机器授权尚未同时就绪。",
  blocked: "任务暂时不能派发，需查看阻塞原因并等待条件恢复。",
  failed_retriable: "上一次尝试因基础设施类故障（传输、超时、进程崩溃）未完成；系统会自动重试，耗尽有界次数才进入终态。科学计算错误不会重试。单元若在求解中途崩溃会重算该单元，已完成单元不受影响。",
  reconcile_pending: "远端结果或执行状态正在由 Control Plane 对账。",
  collecting: "Unit 已结束求解，正在回收并校验输出 manifest。",
  delayed: "执行器仍有心跳，但遥测或传输暂时延迟。",
  stale: "连续监测未成功，系统暂不向该机器派发新任务。",
  disconnected: "SSH/隧道不可达；本地执行可能仍在继续。",
};
const countFormatter = new Intl.NumberFormat("zh-CN");
const timeFormatter = new Intl.DateTimeFormat("zh-CN", {
  month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
  second: "2-digit", hour12: false,
});
const count = (value) => countFormatter.format(value || 0);
export const formatTime = (value) => {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? timeFormatter.format(date) : "-";
};
const eventTarget = (event) => {
  if (event?.subject_type === "machine") return `/app/machines/${event.subject_id}`;
  if (event?.subject_type === "job") return `/app/runs/${event.subject_id}`;
  if (event?.subject_type === "control_operation") return `/app/control/${event.subject_id}`;
  if (event?.details?.job_id) return `/app/runs/${event.details.job_id}`;
  if (event?.details?.machine_id) return `/app/machines/${event.details.machine_id}`;
  return null;
};

function Status({ value, text }) {
  const display = text || label(value);
  return <span className={`status status-${value || "unknown"}`} title={statusHints[value] || undefined} aria-label={statusHints[value] ? `${display}：${statusHints[value]}` : display}><i />{display}</span>;
}

function Brand({ compact = false, to = "/help", onClick }) {
  return <Link className={`brand ${compact ? "brand-compact" : ""}`} to={to} onClick={onClick}>
    <span className="brand-mark"><Network size={18} /></span>
    <span><strong>Research Compute Network</strong><small>科研计算运营网络</small></span>
  </Link>;
}

function PublicHeader() {
  const location = useLocation();
  return <header className="public-header"><Brand to="/connect" /><nav>
    <Link className="button small" to="/help" onClick={() => rememberHelpReturn(location)}><BookOpen size={15} />帮助中心</Link>
  </nav></header>;
}

function Connect() {
  const navigate = useNavigate();
  const [value, setValue] = useState(token());
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event) => {
    event.preventDefault(); setBusy(true); setError(""); setToken(value);
    try { await api("/v1/me"); navigate("/app/overview"); }
    catch (e) { setToken(""); setError(e.message); }
    finally { setBusy(false); }
  };
  return <div className="connect-page"><PublicHeader /><main className="connect-main">
    <section><div className="eyebrow"><ShieldCheck size={16} />受保护的运营入口</div><h1>连接计算网络</h1><p>个人 token 仅保存在当前浏览器会话中。机器 token 不能用于登录，也不会授予运营权限。</p>
      <form onSubmit={submit}><label>个人访问 token<input type="password" value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" placeholder="输入管理员、提交者或机器所有者 token" /></label>{error && <div className="form-error">{error}</div>}<button className="button button-primary" disabled={busy}><KeyRound size={17} />{busy ? "正在验证" : "验证并进入"}</button></form>
      <div className="connect-foot"><CircleHelp size={16} /><span>请输入个人访问 token。</span></div>
    </section><aside><h2>身份边界</h2><dl><div><dt>提交者</dt><dd>提交与查看授权项目任务</dd></div><div><dt>机器所有者</dt><dd>管理本机共享模式与运行</dd></div><div><dt>管理员</dt><dd>查看全局状态、审计与准入</dd></div></dl></aside>
  </main></div>;
}

function useControlPlane(pathname) {
  const [data, setData] = useState(null);
  const [stream, setStream] = useState("connecting");
  const [liveEvent, setLiveEvent] = useState(null);
  const [eventTrail, setEventTrail] = useState([]);
  const [syncMessage, setSyncMessage] = useState("");
  const [nextRefreshAt, setNextRefreshAt] = useState(Date.now() + 15000);
  const [clock, setClock] = useState(Date.now());
  const [refreshing, setRefreshing] = useState(false);
  const [pageVisible, setPageVisible] = useState(() => document.visibilityState !== "hidden");
  const lastSequence = useRef(Number(sessionStorage.getItem("rcn-last-event-sequence") || 0));
  const pathnameRef = useRef(pathname);
  pathnameRef.current = pathname;
  const historyLimit = useRef(50);
  const [resourceErrors, setResourceErrors] = useState({});
  const startup = useRef(null);
  const streamBaselineEstablished = useRef(false);
  const baseline = () => startup.current ||= createStartupBaseline();
  const refresh = usePageRefresh(async ({ signal, isCurrent, resources: affected, reason, since }) => {
    await baseline().ready;
    if (!isCurrent()) return;
    setRefreshing(true);
    if (reason !== "initial") notifyDataRefresh(affected, reason, window, { since });
    const { resources, jobs } = routeResources(pathnameRef.current);
    const reads = Object.entries(resources).filter(([key]) => !affected || affected.includes(key)).map(async ([key, path]) => {
      try {
        const value = await api(path, { signal });
        if (!isCurrent()) return;
        setData((current) => ({ ...(current || {}), [key]: value,
          resourceUpdatedAt: { ...current?.resourceUpdatedAt, [key]: new Date().toISOString() } }));
        setResourceErrors((current) => ({ ...current, [key]: "" }));
      } catch (caught) {
        if (!isCurrent()) return;
        setResourceErrors((current) => ({ ...current, [key]: caught.message }));
        if (caught.status === 401) setData({ unauthorized: true });
      }
    });
    if (jobs && (!affected || affected.includes("jobs"))) reads.push(loadJobsListing((path) => api(path, { signal }), {
      maxJobs: historyLimit.current, history: jobs === "history",
      onProgress: (snapshot) => { if (isCurrent()) setData((current) => applyJobsListing(current, snapshot)); },
    }).catch((caught) => {
      if (isCurrent() && caught.status === 401) setData({ unauthorized: true });
    }));
    await Promise.allSettled(reads);
    if (isCurrent()) { setNextRefreshAt(Date.now() + 15000); setRefreshing(false); }
  }, { key: pathname, initial: true, intervalMs: 15000, listen: false });
  const loadMoreJobs = useCallback(() => { historyLimit.current += 50; return refresh(); }, [refresh]);
  useEffect(() => {
    const stopWatching = watchPageReturn(({ since }) => refresh({ reason: "return", since }));
    const clockTimer = setInterval(() => {
      if (document.visibilityState !== "hidden") setClock(Date.now());
    }, 1000);
    const visibilityChanged = () => {
      const visible = document.visibilityState !== "hidden";
      setPageVisible(visible);
      if (visible) setClock(Date.now());
    };
    document.addEventListener("visibilitychange", visibilityChanged);
    const controller = new AbortController();
    let pendingResources = new Set();
    let invalidateAll = false;
    const requestEvents = (resources) => {
      if (resources === null) invalidateAll = true;
      else for (const resource of resources) pendingResources.add(resource);
    };
    const eventRefresh = createRefreshCoalescer(() => {
      const resources = invalidateAll ? null : [...pendingResources];
      pendingResources = new Set(); invalidateAll = false;
      return refresh({ reason: "state", resources });
    }, { isVisible: () => document.visibilityState !== "hidden" });
    const waitForReconnect = (delayMs = 1200) => new Promise((resolve) => {
      const done = () => { clearTimeout(timeout); controller.signal.removeEventListener("abort", done); resolve(); };
      const timeout = setTimeout(done, delayMs);
      controller.signal.addEventListener("abort", done, { once: true });
    });
    const consume = async () => {
      while (!controller.signal.aborted) {
        let reconnectDelay = 1200;
        try {
          lastSequence.current = await connectStateStream(async (event) => {
            if (event?._connected) {
              const latest = Number(event.latest_sequence || 0);
              if (!streamBaselineEstablished.current) {
                streamBaselineEstablished.current = true;
                const joinsInitial = baseline().establish();
                setStream("syncing");
                await refresh({ reason: joinsInitial ? "initial" : "baseline", join: joinsInitial });
                lastSequence.current = latest;
                sessionStorage.setItem("rcn-last-event-sequence", String(latest));
                setSyncMessage(""); setStream("connected");
                return { resume_sequence: latest };
              }
              if (latest < lastSequence.current) {
                setSyncMessage(lastSequence.current
                  ? "事件序列已重置，正在重新同步状态"
                  : "正在建立实时状态基线");
                setStream("syncing");
                requestEvents(null);
                await eventRefresh.flush();
                lastSequence.current = latest;
                sessionStorage.setItem("rcn-last-event-sequence", String(latest));
                setSyncMessage("");
                setStream("connected");
                return { resume_sequence: latest };
              } else {
                setSyncMessage("");
                setStream("connected");
              }
              return;
            }
            const sequence = Number(event?.sequence || 0);
            if (!sequence || sequence <= lastSequence.current) return;
            if (lastSequence.current && sequence > lastSequence.current + 1) {
              setLiveEvent(null);
              setSyncMessage(`事件序列缺口 ${lastSequence.current + 1}-${sequence - 1}，等待状态同步`);
              setStream("syncing");
              requestEvents(null);
              await eventRefresh.flush();
              setSyncMessage("");
              setStream("connected");
            }
            lastSequence.current = sequence;
            sessionStorage.setItem("rcn-last-event-sequence", String(sequence));
            const received = { ...event, received_at: Date.now() };
            setLiveEvent(received);
            setTimeout(() => setLiveEvent((current) => current?.event_id === received.event_id ? null : current), 2600);
            setEventTrail((current) => [received, ...current.filter((item) => item.event_id !== received.event_id)].slice(0, 40));
            if (eventAffectsRoute(pathnameRef.current, event)) {
              requestEvents(eventResources(event)); eventRefresh.schedule();
            }
          }, setStream, controller.signal, { lastSequence: lastSequence.current });
        } catch (eventError) {
          if (controller.signal.aborted) break;
          reconnectDelay = Math.max(1200, Math.min(10000, Number(eventError.retryAfterMs) || 1200));
          baseline().release();
          setStream("reconnecting");
          setSyncMessage(eventError.message || "实时连接中断，正在重连");
        }
        if (!controller.signal.aborted) await waitForReconnect(reconnectDelay);
      }
    };
    consume();
    return () => { stopWatching(); clearInterval(clockTimer); document.removeEventListener("visibilitychange", visibilityChanged); eventRefresh.cancel(); baseline().release(); controller.abort(); };
  }, [refresh]);
  return {
    data, error: Object.entries(resourceErrors).filter(([key, value]) => value && key in routeResources(pathname).resources)
      .map(([key, value]) => `${key}：${value}${data?.resourceUpdatedAt?.[key] ? `（保留 ${formatTime(data.resourceUpdatedAt[key])} 的内容）` : ""}`).join("；"), stream, liveEvent, eventTrail, syncMessage, refresh, loadMoreJobs, refreshing, pageVisible,
    refreshIn: Math.max(0, Math.ceil((nextRefreshAt - clock) / 1000)),
  };
}

function SyncCountdown({ remaining, cycle = 15, stream, refreshing, paused = false, onRefresh }) {
  const progress = Math.max(0, Math.min(1, Number(remaining) / cycle));
  return <button className={`sync-countdown ${refreshing ? "is-refreshing" : ""} ${paused ? "is-paused" : ""}`} type="button" title={paused ? "页面位于后台，倒计时动画已暂停；点击立即刷新" : "查看同步状态并立即刷新"} aria-label={`下次同步 ${remaining} 秒，点击立即刷新`} onClick={onRefresh}>
    <svg viewBox="0 0 36 36" aria-hidden="true"><circle className="sync-countdown-track" cx="18" cy="18" r="15" /><circle className={`sync-countdown-progress sync-${stream}`} cx="18" cy="18" r="15" pathLength="1" strokeDasharray={`${progress} 1`} /></svg>
    <span>{refreshing ? "…" : `${remaining}`}</span>
  </button>;
}

function AppShell() {
  const location = useLocation();
  const { data, error, stream, liveEvent, eventTrail, syncMessage, refresh, loadMoreJobs, refreshIn, refreshing, pageVisible } = useControlPlane(location.pathname);
  const navigate = useNavigate();
  const restoredHelpScroll = useRef(null);
  const [navOpen, setNavOpen] = useState(false);
  useEffect(() => {
    if (!data || location.state?.helpReturnScrollY == null) return;
    const restoreKey = `${location.key}:${location.state.helpReturnScrollY}`;
    if (restoredHelpScroll.current === restoreKey) return;
    restoredHelpScroll.current = restoreKey;
    requestAnimationFrame(() => requestAnimationFrame(() => {
      window.scrollTo({ top: Number(location.state.helpReturnScrollY || 0) });
    }));
  }, [data, location.state]);
  if (!data && !error) return <Loading full />;
  if (data?.unauthorized) return <Navigate to="/connect" replace />;
  const logout = () => { setToken(""); navigate("/connect"); };
  const admin = (data?.me?.roles || []).includes("admin");
  return <div className="app-shell"><aside className={navOpen ? "app-nav open" : "app-nav"}>
    <Brand compact to="/app/overview" /><nav>
      <NavLink to="/app/overview" onClick={() => setNavOpen(false)}><Gauge size={18} />集群总览</NavLink>
      <NavLink to="/app/fleet" onClick={() => setNavOpen(false)}><Server size={18} />机器集群</NavLink>
      <NavLink to="/app/map" onClick={() => setNavOpen(false)}><Network size={18} />网络拓扑</NavLink>
      <NavLink to="/app/runs" onClick={() => setNavOpen(false)}><Boxes size={18} />任务运行</NavLink>
      <NavLink to="/app/projects" onClick={() => setNavOpen(false)}><Users size={18} />项目与接入</NavLink>
      <NavLink to="/app/operations" onClick={() => setNavOpen(false)}><MonitorCog size={18} />运营与审计</NavLink>
      {admin && <NavLink to="/app/control" onClick={() => setNavOpen(false)}><SlidersHorizontal size={18} />控制中心</NavLink>}
      {admin && <NavLink to="/app/alerts" onClick={() => setNavOpen(false)}><AlertTriangle size={18} />告警中心</NavLink>}
      {admin && <NavLink to="/app/admin" onClick={() => setNavOpen(false)}><ShieldCheck size={18} />管理员面板</NavLink>}
      <NavLink to="/app/help" onClick={() => { rememberHelpReturn(location); setNavOpen(false); }}><BookOpen size={18} />帮助与文档</NavLink>
    </nav><div className="nav-account"><div><span>{data?.me?.actor_id || "-"}</span><small>{(data?.me?.roles || []).map(label).join(" · ")}</small></div><button title="退出当前会话" onClick={logout}><LogOut size={17} /></button></div>
  </aside><section className="app-workspace"><header className="workspace-header">
    <button className="nav-toggle" onClick={() => setNavOpen(!navOpen)}><Menu size={19} /></button>
    <div className="connection"><i className={stream} /><span>{stream === "connected" ? "事件连接正常" : stream === "syncing" ? "正在同步" : "正在重连"}</span><small>{location.pathname === "/app/overview" ? "统计快照时间见下方" : <>总览更新 {formatTime(data?.overview?.generated_at)}</>}</small><SyncCountdown remaining={refreshIn} stream={stream} refreshing={refreshing} paused={!pageVisible} onRefresh={refresh} /></div>
    <Link className="icon-button" title="帮助与文档" to="/app/help" onClick={() => rememberHelpReturn(location)}><CircleHelp size={17} /></Link>
    <button className="icon-button" title="刷新" onClick={refresh}><RefreshCw size={17} /></button>
  </header>{error && <div className="inline-error"><AlertTriangle size={16} />{error}</div>}{syncMessage && <div className="sync-warning"><RefreshCw size={15} />{syncMessage}</div>}
    <MetadataRecovery actorId={data?.me?.actor_id} onRecovered={refresh} />
    <Suspense fallback={<Loading />}><Routes><Route path="overview" element={<main className="app-page"><ClusterInsights /></main>} /><Route path="fleet" element={<Fleet data={data} liveEvent={liveEvent} refresh={refresh} />} /><Route path="machines/:machineId" element={<MachineDetail machines={data?.overview?.machines} admin={admin} roles={data?.me?.roles || []} actorId={data?.me?.actor_id} settings={data?.settings} onGlobalRefresh={refresh} />} /><Route path="compare" element={<FleetCompare />} /><Route path="map" element={<NetworkMap data={data} liveEvent={liveEvent} stream={stream} />} /><Route path="runs" element={<Runs data={data} liveEvent={liveEvent} refresh={refresh} loadMore={loadMoreJobs} />} /><Route path="runs/:jobId" element={<JobDetail admin={admin} />} /><Route path="projects" element={<Projects actorId={data?.me?.actor_id} roles={data?.me?.roles || []} onGlobalRefresh={refresh} />} /><Route path="operations" element={<Operations data={data} refresh={refresh} liveEvent={liveEvent} eventTrail={eventTrail} />} />{admin && <Route path="control" element={<ControlCenter onGlobalRefresh={refresh} />} />}{admin && <Route path="control/:operationId" element={<ControlOperationDetail />} />}{admin && <Route path="alerts" element={<AlertCenter />} />}{admin && <Route path="admin" element={<AdminConsole overview={data?.overview} actorId={data?.me?.actor_id} onGlobalRefresh={refresh} />} />}<Route path="help" element={<HelpCenter embedded />} /><Route path="help/:slug" element={<HelpCenter embedded />} /><Route index element={<Navigate to="overview" replace />} /></Routes></Suspense>
  </section></div>;
}

function PageTitle({ eyebrow, title, detail, actions }) {
  return <div className="page-title"><div><span>{eyebrow}</span><h1>{title}</h1><p>{detail}</p></div>{actions && <div className="page-actions">{actions}</div>}</div>;
}
function Metric({ icon: Icon, label: text, value, detail, tone = "" }) {
  return <div className={`metric ${tone}`}><Icon size={18} /><div><span>{text}</span><strong>{value}</strong><small>{detail}</small></div></div>;
}
function Resource({ value, average = null, averageLabel = "均", kind = "cpu", inactive = false, frozen = false, detail = "", tooltipDetail = "" }) {
  const stateClass = `${inactive ? " resource-inactive" : ""}${frozen ? " resource-frozen" : ""}`;
  const resourceName = { cpu: "CPU", gpu: "GPU", memory: "内存", disk: "磁盘" }[kind] || kind;
  if (inactive) return <div className={`resource resource-${kind}${stateClass}`} title={`${resourceName}：${detail || "未配置"}`}><span>—</span><small>{detail || "未配置"}</small></div>;
  const normalized = Math.max(0, Math.min(100, Math.round(value || 0)));
  const level = normalized >= 85 ? "high" : normalized >= 60 ? "medium" : "normal";
  const title = `${resourceName} 主值 ${normalized}%${average != null ? `，${averageLabel} ${Math.round(average)}%` : ""}${tooltipDetail || detail ? `，${tooltipDetail || detail}` : ""}${frozen ? "；遥测过期，显示最后有效值" : ""}`;
  return <div className={`resource resource-${kind} level-${level}${stateClass}`} title={title}><span>{normalized}%{average != null ? ` · ${averageLabel} ${Math.round(average)}%` : ""}</span><div><i style={{ width: `${normalized}%` }} /></div>{detail && <small>{detail}{frozen ? " · 最后有效值" : ""}</small>}</div>;
}

function metricTimestamp(machine, runtime) {
  return runtime.last_metric_at || machine.metrics?.observed_at;
}

function MachineHealth({ machine, runtime }) {
  const metricAt = metricTimestamp(machine, runtime);
  const heartbeatAt = runtime.last_supervisor_heartbeat_at || machine.last_heartbeat_at;
  if (runtime.transport_state === "disconnected") {
    return <div className="machine-health"><Status value="warning" text="传输断开" /><small>{heartbeatAt ? `执行器最后确认于 ${formatAge(heartbeatAt)}` : "等待出站心跳确认执行器"}</small></div>;
  }
  if (runtime.heartbeat_phase === "healthy" && runtime.telemetry_state === "live") {
    return <div className="machine-health"><Status value="live" text="执行器在线 · 遥测实时" /><small>数据于 {formatAge(metricAt)}</small></div>;
  }
  if (runtime.heartbeat_phase === "delayed") {
    return <div className="machine-health"><Status value="warning" text="执行器在线 · 数据延迟" /><small>最后有效数据于 {formatAge(metricAt)}</small></div>;
  }
  if (runtime.heartbeat_phase === "stale") {
    return <div className="machine-health"><Status value="stale" text="执行器心跳过期" /><small>最后心跳于 {formatAge(heartbeatAt)}</small></div>;
  }
  if (runtime.heartbeat_phase === "offline") {
    return <div className="machine-health"><Status value="offline" text="执行器不可用" /><small>{heartbeatAt ? `最后心跳于 ${formatAge(heartbeatAt)}` : "尚无有效心跳"}</small></div>;
  }
  if (runtime.supervisor_state === "online" && runtime.telemetry_state === "stale") {
    return <div className="machine-health"><Status value="warning" text="执行器在线 · 数据延迟" /><small>最后有效数据于 {formatAge(metricAt)}</small></div>;
  }
  if (runtime.supervisor_state === "online") {
    return <div className="machine-health"><Status value="warning" text="执行器在线 · 暂无遥测" /><small>等待首个有效采样</small></div>;
  }
  if (runtime.supervisor_state === "stale") {
    return <div className="machine-health"><Status value="stale" text="执行器心跳过期" /><small>最后心跳于 {formatAge(heartbeatAt)}</small></div>;
  }
  return <div className="machine-health"><Status value="offline" text="执行器不可用" /><small>{heartbeatAt ? `最后心跳于 ${formatAge(heartbeatAt)}` : "尚无有效心跳"}</small></div>;
}

function Fleet({ data, liveEvent, refresh }) {
  const overview = data?.overview || {};
  const admin = (data?.me?.roles || []).includes("admin");
  const [params, setParams] = useSearchParams();
  const query = params.get("q") || "";
  const selectedId = params.get("drawer");
  const drawerTab = params.get("tab") || "overview";
  const { rows, historical, historicalMatches, selectedIds } = fleetRecords(overview.machines, query, params.get("selected") || "");
  const [control, setControl] = useState(null);
  const [targetDrafts, setTargetDrafts] = useState({});
  const [batchTarget, setBatchTarget] = useState(0);
  const [capacityNotice, setCapacityNotice] = useState("");
  const updateParams = (updates) => {
    const next = new URLSearchParams(params);
    Object.entries(updates).forEach(([key, value]) => value ? next.set(key, value) : next.delete(key));
    setParams(next);
  };
  const toggleMachine = (machineId) => {
    const next = selectedIds.includes(machineId) ? selectedIds.filter((id) => id !== machineId) : [...selectedIds, machineId].slice(0, 5);
    updateParams({ selected: next.join(",") });
  };
  const showDrawer = (machineId, tab = "overview") => updateParams({ drawer: machineId, tab });
  const beginBatchMode = (mode) => setControl({ action: "set_admin_mode", title: `批量${label(mode)}`, targets: selectedIds.map((machine_id) => ({ machine_id, requested_mode: mode })) });
  const capacityByMachine = useMemo(
    () => Object.fromEntries((overview.capacity || []).map((item) => [item.machine_id, item])),
    [overview.capacity],
  );
  const batchHardCap = selectedIds.length ? Math.min(...selectedIds.map((machineId) => {
    const policy = overview.policies?.[machineId] || {};
    const config = overview.execution_configs?.[machineId] || {};
    return Math.min(policy.max_concurrent_units || 0, config.max_concurrent_units || policy.max_concurrent_units || 0);
  })) : 0;
  const summary = overview.fleet_summary || overview.summary || {};
  const alertCount = summary.alert_count ?? (overview.alerts || []).length;
  const activityMismatches = rows.map((machine) => ({
    id: machine.machine_id,
    scheduled: Number(machine.scheduled_running_units ?? machine.metrics?.running_units ?? 0),
    telemetry: Number(machine.telemetry_running_units ?? machine.metrics?.running_units ?? 0),
  })).filter((machine) => machine.scheduled !== machine.telemetry);
  const complete = async () => {
    if (control?.action === "set_target_capacity") {
      const requested = control.targets.map((target) => `${target.machine_id}=${target.target_concurrent_units}`).join(" · ");
      setCapacityNotice(`目标并发已保存（${requested}）。有效并发仍会受到压力、遥测、Profile 与资源门槛限制。`);
      setTargetDrafts((current) => {
        const next = { ...current };
        control.targets.forEach((target) => delete next[target.machine_id]);
        return next;
      });
    }
    await refresh();
  };
  return <main className="app-page"><PageTitle eyebrow="FLEET / LIVE" title="机器集群" detail="所有状态、资源、容量与告警均可继续下钻" actions={<><HelpLink topic="machineHealth" /><label className="search"><Search size={16} /><input value={query} onChange={(e) => updateParams({ q: e.target.value })} placeholder="搜索机器、所有者或能力" /></label></>} />
    <Suspense fallback={<DataLoadState compact label="正在加载集群工作摘要" />}><ClusterInsights compact /></Suspense>
    {capacityNotice && <div className="inline-success capacity-notice" role="status"><CheckCircle2 size={16} /><span>{capacityNotice}</span><button className="icon-button" title="关闭提示" onClick={() => setCapacityNotice("")}><X size={14} /></button></div>}
    {activityMismatches.length > 0 && <div className="fleet-activity-mismatch" role="status" title="活动 Unit 以调度器的 Attempt 状态为准；遥测可能因心跳延迟暂时欠报"><AlertTriangle size={15} /><span>活动 Unit 以调度记录为准：{activityMismatches.map((machine) => `${machine.id} 调度 ${machine.scheduled} · 遥测 ${machine.telemetry}`).join("；")}</span></div>}
    {!admin && data?.settings?.visibility === "own_detail" && <p className="fleet-scope-note">仅显示你拥有的机器；群组汇总不代表你有权查看其他成员的机器详情。</p>}
    {!admin && data?.settings?.visibility === "own_detail" && <FleetGroupSummary />}
    <div className="metric-strip"><Metric icon={Server} label="在线机器" value={`${summary.online_machines || 0} / ${summary.total_machines ?? (overview.machines || []).length}`} detail={`现役 ${summary.offline_machines || 0} 台离线 · 历史 ${historical.length} 条`} tone="good" /><Metric icon={Cpu} label="可用 CPU" value={count(summary.available_cpus)} detail="符合调度条件" /><Metric icon={MemoryStick} label="可用内存" value={`${count(Math.round((summary.available_memory_mb || 0) / 1024))} GiB`} detail="开放节点合计" /><Metric icon={AlertTriangle} label="活动告警" value={count(alertCount)} detail="现役记录 · 需要人工查看" tone={alertCount ? "warn" : "good"} /></div>
    {selectedIds.length > 0 && <div className="batch-bar"><div><b>已选择 {selectedIds.length} 台</b><span>{selectedIds.join(" · ")}</span></div>{admin && <><button onClick={() => beginBatchMode("open")}>开放</button><button onClick={() => beginBatchMode("drain")}>排空</button><button onClick={() => beginBatchMode("paused")}>暂停</button><div className="batch-capacity"><label>目标并发<input aria-label="批量目标并发" type="number" min="0" max={batchHardCap} value={Math.min(batchTarget, batchHardCap)} onChange={(event) => setBatchTarget(Math.max(0, Math.min(batchHardCap, Number(event.target.value))))} /></label><button onClick={() => setControl({ action: "set_target_capacity", title: `批量目标并发 ${Math.min(batchTarget, batchHardCap)}`, targets: selectedIds.map((machine_id) => ({ machine_id, target_concurrent_units: Math.min(batchTarget, batchHardCap) })) })}>应用</button></div><button onClick={() => setControl({ action: "health_probe", title: "批量健康检查", targets: selectedIds.map((machine_id) => ({ machine_id })) })}>健康检查</button></>}<Link className={`button small ${selectedIds.length < 2 ? "disabled" : ""}`} aria-disabled={selectedIds.length < 2} to={selectedIds.length >= 2 ? `/app/compare?machines=${selectedIds.join(",")}` : "#"}><GitCompareArrows size={15} />对比</Link><button className="icon-button" title="清除选择" onClick={() => updateParams({ selected: "" })}><X size={16} /></button></div>}
    <section className="data-section"><div className="section-heading"><div><h2>节点清单</h2><span>{rows.length} 条可见记录 · 性能采样随心跳同步</span></div></div><div className="table-wrap fleet-table-wrap"><table className="fleet-table"><thead><tr><th>机器</th><th>执行器 / 遥测</th><th className="fleet-mode-column">有效模式 / 管理员覆盖</th><th className="performance-head cpu">CPU</th><th className="performance-head gpu">GPU</th><th className="performance-head memory">内存</th><th className="performance-head disk fleet-disk-column">磁盘</th><th>活动单元</th><th>有效 / 目标</th><th className="fleet-runtime-column">运行时</th><th /></tr></thead><tbody>{rows.map((m) => {
      const runtime = overview.operational_statuses?.[m.machine_id] || {};
      const policy = overview.policies?.[m.machine_id] || {};
      const config = overview.execution_configs?.[m.machine_id] || {};
       const telemetryLive = runtime.telemetry_state === "live";
       const hasMetrics = Boolean(m.metrics?.observed_at) && m.metrics?.available !== false;
       const cpu = Math.round(m.metrics?.cpu_current_percent ?? m.metrics?.cpu_total_percent ?? 0);
       const cpuAverage = m.metrics?.cpu_average_percent ?? cpu;
       const memory = m.total_memory_mb && hasMetrics ? Math.round((1 - (m.metrics?.available_memory_mb || 0) / m.total_memory_mb) * 100) : 0;
      const gpu = gpuDisplay(m);
       const disk = m.metrics?.total_disk_mb && hasMetrics ? Math.round((m.metrics.disk_used_mb || 0) / m.metrics.total_disk_mb * 100) : 0;
       const runtimeVersion = config.runtime_version || m.runtime_version || "-";
       const pressureEvent = liveEvent?.subject_id === m.machine_id && liveEvent?.event_type === "machine.pressure_changed";
       const staticCap = Math.min(policy.max_concurrent_units || 0, config.max_concurrent_units || policy.max_concurrent_units || 0);
       const effectiveCap = runtime.effective_capacity ?? runtime.effective_comsol_concurrency ?? staticCap;
       const savedTargetCap = config.target_concurrent_units ?? staticCap;
       const reportedCap = runtime.supervisor_reported_concurrent_units;
       const targetCap = targetDrafts[m.machine_id] ?? config.target_concurrent_units ?? staticCap;
       const scheduledUnits = Number(m.scheduled_running_units ?? m.metrics?.running_units ?? 0);
       const assignedUnits = Number(m.scheduled_assigned_units ?? 0);
       const collectingUnits = Number(m.scheduled_collecting_units ?? 0);
       const telemetryUnits = Number(m.telemetry_running_units ?? m.metrics?.running_units ?? 0);
       const unitCountMismatch = scheduledUnits !== telemetryUnits;
       const capacity = capacityDisplay({ effective: effectiveCap, target: savedTargetCap, hardCap: staticCap, pressureState: runtime.pressure_state });
       const dispatchCapacity = capacityByMachine[m.machine_id] || {};
       const preparedReservations = Number(dispatchCapacity.prepared_reservations || 0);
       const reservedSlots = Number(dispatchCapacity.reserved_slots || 0);
       const physicalAvailableSlots = Number(dispatchCapacity.physical_available_slots || 0);
       const overcommittedSlots = Number(dispatchCapacity.overcommitted_slots || 0);
       const draftChanged = Number(targetCap) !== Number(savedTargetCap);
       return <tr className={pressureEvent ? "event-flash" : ""} key={m.machine_id}><td><div className="machine-identity"><input type="checkbox" aria-label={`选择 ${m.machine_id}`} checked={selectedIds.includes(m.machine_id)} onChange={() => toggleMachine(m.machine_id)} /><button className="row-primary" onClick={() => showDrawer(m.machine_id)}><b>{m.display_name || m.machine_id}</b><small>{m.machine_id} · {m.owner_user_id}</small></button></div></td><td><button className="cell-drill" onClick={() => showDrawer(m.machine_id, "runtime")}><MachineHealth machine={m} runtime={runtime} /></button></td><td className="fleet-mode-column"><div className="mode-stack"><Status value={policy.admin_mode_override || policy.owner_mode || "unknown"} /><small>所有者策略：{label(policy.owner_mode)}{policy.admin_mode_override ? ` · 管理员覆盖：${label(policy.admin_mode_override)}` : ""}</small>{admin && <><small className="mode-hint">变更需预览并确认</small><select title="选择管理员覆盖操作；不会直接生效" aria-label={`${m.machine_id} 管理员覆盖操作`} value="" onChange={(event) => { const value = event.target.value; if (!value) return; setControl(value === "clear" ? { action: "clear_admin_mode", title: `${m.machine_id} · 清除管理员覆盖`, targets: [{ machine_id: m.machine_id }] } : { action: "set_admin_mode", title: `${m.machine_id} · ${label(value)}`, targets: [{ machine_id: m.machine_id, requested_mode: value }] }); }}><option value="">选择覆盖操作…</option><option value="open">开放：接收新派发</option><option value="drain">排空：等待现有任务完成</option><option value="paused">暂停：停止新派发</option>{policy.admin_mode_override && <option value="clear">清除管理员覆盖</option>}</select></>}</div></td><td className="performance-cell"><button className="cell-drill" onClick={() => showDrawer(m.machine_id, "performance")}><Resource value={cpu} average={cpuAverage} kind="cpu" inactive={!hasMetrics} frozen={hasMetrics && !telemetryLive} detail={`${m.total_cpus || 0} 线程`} /></button></td><td className="performance-cell"><button className="cell-drill" onClick={() => showDrawer(m.machine_id, "performance")}><Resource value={gpu.value} average={gpu.average} averageLabel="当前" kind="gpu" inactive={gpu.inactive} frozen={!gpu.inactive && !telemetryLive} detail={gpu.tableDetail} tooltipDetail={gpu.detail} /></button></td><td className="performance-cell"><button className="cell-drill" onClick={() => showDrawer(m.machine_id, "performance")}><Resource value={memory} kind="memory" inactive={!hasMetrics} frozen={hasMetrics && !telemetryLive} detail={hasMetrics ? `${Math.round((m.metrics?.available_memory_mb || 0) / 1024)} GiB 可用` : "暂无遥测"} /></button></td><td className="performance-cell fleet-disk-column"><button className="cell-drill" onClick={() => showDrawer(m.machine_id, "performance")}><Resource value={disk} kind="disk" inactive={!hasMetrics} frozen={hasMetrics && !telemetryLive} detail={hasMetrics ? `${Math.round((m.metrics?.free_disk_mb || 0) / 1024)} GiB 可用` : "暂无遥测"} /></button></td><td><button className="cell-drill text-cell" title={`实际运行 ${scheduledUnits}；排队/预备 ${assignedUnits}；回收 ${collectingUnits}；遥测 ${telemetryUnits}；预备 slot ${preparedReservations}`} onClick={() => showDrawer(m.machine_id, "tasks")}><strong>{scheduledUnits}</strong><small className="cell-sub">运行中 · 排队/预备 {assignedUnits}</small>{collectingUnits > 0 && <small className="cell-sub">回收中 {collectingUnits}</small>}{preparedReservations > 0 && <small className="cell-sub">standby {preparedReservations}</small>}{physicalAvailableSlots > 0 && <small className="cell-sub">并发位余量 {physicalAvailableSlots}</small>}{overcommittedSlots > 0 && <small className="cell-sub capacity-reduced">超出当前准入 {overcommittedSlots}</small>}</button></td><td><div className="capacity-control"><button className="cell-drill text-cell" title={`${runtime.capacity_reason || capacity.detail}；Supervisor 实报 ${reportedCap ?? "未知"}；并发位余量 ${physicalAvailableSlots}（仍须通过资源、solver 与权限门槛）；已保留 ${reservedSlots}；已预备 ${preparedReservations}`} onClick={() => showDrawer(m.machine_id, "capacity")}><strong className={capacity.constrained ? "capacity-reduced" : ""}>有效 {effectiveCap}</strong><small className="cell-sub">目标 {savedTargetCap} · 实报 {reportedCap ?? "-"}</small><small className="cell-sub">待准入 {dispatchCapacity.available_slots ?? 0} · 预备 {preparedReservations}</small>{runtime.capacity_drift && <small className="cell-sub capacity-reduced">容量漂移</small>}{config.hard_capacity_pending_acceptance && <small className="cell-sub capacity-reduced">管理员强制 · 待验收</small>}</button>{admin && <div><input aria-label={`${m.machine_id} 目标并发`} className={draftChanged ? "capacity-draft" : ""} type="number" min="0" max={staticCap} value={targetCap} onChange={(event) => setTargetDrafts((current) => ({ ...current, [m.machine_id]: Number(event.target.value) }))} /><button title={draftChanged ? `预览保存目标并发 ${targetCap}` : "目标并发没有变化"} disabled={!draftChanged} onClick={() => setControl({ action: "set_target_capacity", title: `${m.machine_id} · 目标并发 ${targetCap}`, targets: [{ machine_id: m.machine_id, target_concurrent_units: Number(targetCap) }] })}><CheckCircle2 size={13} /></button></div>}</div></td><td className="fleet-runtime-column"><button className="cell-drill text-cell" onClick={() => showDrawer(m.machine_id, "config")}><code>{runtimeVersion.slice(0, 10)}</code><small className="cell-sub">协议 {m.protocol_version}</small></button></td><td><Link className="icon-button" title="打开完整机器详情" to={`/app/machines/${m.machine_id}`}><ChevronRight size={17} /></Link></td></tr>;
    })}</tbody></table>{!rows.length && <Empty icon={Server} text="没有匹配的机器" />}</div></section>
     <FleetHistory records={historical} matches={historicalMatches} query={query} />
     {selectedId && data?.me?.actor_id && overview.machines?.some((machine) => machine.machine_id === selectedId && !isHistorical(machine)) && <MachineDrawer key={`${data.me.actor_id}:${selectedId}`} actorId={data.me.actor_id} machine={overview.machines.find((machine) => machine.machine_id === selectedId)} overview={overview} settings={data?.settings} admin={admin} initialTab={drawerTab} refresh={refresh} onClose={() => updateParams({ drawer: "", tab: "" })} />}
     {control && <MachineControlDialog {...control} onClose={() => setControl(null)} onComplete={complete} />}
  </main>;
}

function MachineDrawer({ actorId, machine, overview, settings, admin, initialTab = "overview", refresh, onClose }) {
  const pressure = usePressureOverride(actorId, machine.machine_id, refresh);
  const { preview, busy, error: controlError } = pressure;
  const runtime = overview.operational_statuses?.[machine.machine_id] || {};
  const policy = overview.policies?.[machine.machine_id] || {};
  const config = overview.execution_configs?.[machine.machine_id] || {};
  const gpu = gpuDisplay(machine);
  const metricsAvailable = machine.metrics?.available !== false;
  const [reason, setReason] = useState("");
  const hardCap = Math.min(policy.max_concurrent_units || 1, config.max_concurrent_units || 1);
  const maxOverrideMinutes = settings?.pressure_policy?.max_override_minutes || 30;
  const [overrideCap, setOverrideCap] = useState(Math.max(1, Math.min(hardCap, config.target_concurrent_units || hardCap)));
  const [overrideMinutes, setOverrideMinutes] = useState(Math.min(30, maxOverrideMinutes));
  const previewOverride = () => pressure.createPreview({ reason, ttl_minutes: overrideMinutes, requested_concurrent_units: overrideCap });
  const confirmOverride = pressure.confirm;
  return <Drawer title={machine.display_name || machine.machine_id} subtitle={machine.machine_id} onClose={onClose}>
    <div className="drawer-status"><MachineHealth machine={machine} runtime={runtime} /><Status value={policy.admin_mode_override || policy.owner_mode} /></div>
    <div className="drawer-deep-actions"><Link className="button button-primary" to={`/app/machines/${machine.machine_id}?tab=${initialTab === "runtime" ? "overview" : initialTab}`} onClick={onClose}>打开完整详情 <ChevronRight size={15} /></Link><Link className="button" to={`/app/machines/${machine.machine_id}?tab=events`} onClick={onClose}>事件与审计</Link></div>
    <Description rows={[["所有者", machine.owner_user_id], ["所有者模式", label(policy.owner_mode)], ["管理员覆盖", policy.admin_mode_override ? label(policy.admin_mode_override) : "无"], ["最终有效模式", label(policy.admin_mode_override || policy.owner_mode)], ["能力", (machine.capabilities || []).join(", ") || "-"], ["CPU", metricsAvailable ? `${Math.round(machine.metrics?.cpu_current_percent ?? machine.metrics?.cpu_total_percent ?? 0)}% · 均 ${Math.round(machine.metrics?.cpu_average_percent ?? 0)}% · ${machine.total_cpus || 0} 线程` : "未知"], ["GPU", metricsAvailable ? gpu.summary : "未知"], ["内存", metricsAvailable ? `${Math.round((machine.metrics?.memory_used_mb || 0) / 1024)} / ${Math.round((machine.total_memory_mb || 0) / 1024)} GiB` : "未知"], ["磁盘", metricsAvailable ? `${Math.round((machine.metrics?.disk_used_mb || 0) / 1024)} / ${Math.round((machine.total_disk_mb || 0) / 1024)} GiB` : "未知"], ["压力", `${runtime.pressure_state || "normal"} · ${runtime.capacity_reason || "无外部压力"}`], ["有效并发", runtime.effective_capacity ?? runtime.effective_comsol_concurrency ?? Math.min(policy.max_concurrent_units || 0, config.max_concurrent_units || policy.max_concurrent_units || 0)], ["目标并发", config.target_concurrent_units ?? "-"], ["硬上限", Math.min(policy.max_concurrent_units || 0, config.max_concurrent_units || policy.max_concurrent_units || 0)], ["容量判定", formatAge(runtime.capacity_decision_at)], ["运行时", config.runtime_version || machine.runtime_version || "-"], ["最近心跳", formatTime(runtime.last_supervisor_heartbeat_at || machine.last_heartbeat_at)], ["指标采样", formatAge(metricTimestamp(machine, runtime))], ["执行配置", config.enabled ? "已启用" : "未启用"], ["数值状态", runtime.numeric_equivalence || "pending"]]} />
    <div className={`host-consent ${policy.external_comsol_termination_authorized === false ? "disabled" : "enabled"}`}><ShieldCheck size={16} /><div><b>外部 COMSOL break-glass</b><span>{policy.external_comsol_termination_authorized === false ? "机器所有者已关闭；管理员不能终止非 Network COMSOL" : "机器所有者已授权；仍需进程集 hash、break-glass 和二次确认"}</span></div></div>
    <h3>当前工作单元</h3>{(machine.running_work_unit_ids || []).length ? <ul className="mono-list">{machine.running_work_unit_ids.map((id) => <li key={id}>{id}</li>)}</ul> : <Empty icon={Activity} text="当前没有运行中的工作单元" compact />}
    {admin && <section className="drawer-control"><h3>临时压力覆盖</h3><p>在执行器与遥测实时的前提下，明确允许受压机器继续接收指定数量的新计算任务。Profile、内存、磁盘、solver 资格和静态硬上限仍是硬门槛。</p>
      {!preview ? <><div className="override-grid"><label>覆盖并发<input type="number" min="1" max={hardCap} value={overrideCap} onChange={(event) => setOverrideCap(Math.max(1, Math.min(hardCap, Number(event.target.value))))} /></label><label>有效分钟<input type="number" min="1" max={maxOverrideMinutes} value={overrideMinutes} onChange={(event) => setOverrideMinutes(Math.max(1, Math.min(maxOverrideMinutes, Number(event.target.value))))} /></label></div><label>审计原因<input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="填写本次覆盖的明确原因" /></label><button className="button" disabled={busy || !reason.trim() || runtime.supervisor_state !== "online" || runtime.telemetry_state !== "live"} onClick={previewOverride}><ShieldCheck size={16} />预览影响</button></>
        : <div className="control-preview"><Description rows={[["机器", preview.machine_id], ["覆盖并发", preview.requested_concurrent_units], ["覆盖至", formatTime(preview.requested_until)], ["原因", preview.reason], ["静态硬上限", hardCap]]} /><div><button className="button" disabled={busy || pressure.locked} onClick={pressure.edit}>返回修改</button>{pressure.locked && <button className="button" disabled={busy} onClick={pressure.recover}>核对原覆盖结果</button>}<button className="button button-primary" disabled={busy} onClick={confirmOverride}><CheckCircle2 size={16} />{pressure.locked ? "重试原覆盖票据" : "确认覆盖"}</button></div></div>}
      {pressure.notice && <p role="status">{pressure.notice}</p>}{pressure.locked && <p role="status">原覆盖票据已提交，恢复不会生成新预览或延长原有效期。</p>}
      {controlError && <div className="form-error">{controlError}</div>}
    </section>}
  </Drawer>;
}

function EventPath({ event }) {
  if (!event) return null;
  const type = event.event_type || "";
  let active = [2];
  if (type.startsWith("partition_plan.") || type === "job.submitted") active = [0, 1, 2];
  else if (["work_unit.assigned", "work_unit.started", "attempt.submitted"].includes(type)) active = [2, 3];
  else if (["attempt.collected", "work_unit.completed"].includes(type)) active = [3, 4];
  else if (type.includes("failed") || type.includes("retried") || type.includes("reconcile")) active = [3, 2];
  const machineId = event.details?.machine_id || (event.subject_type === "machine" ? event.subject_id : null);
  const stages = ["Workbench", "Planner", "Control Plane", machineId || "执行节点", "Origin staging"];
  const target = eventTarget(event);
  return <div className="event-path" key={event.event_id} aria-label={`${type} ${event.subject_id}`}>
    <header><Activity size={15} />{target ? <Link to={target}><b>{type}</b></Link> : <b>{type}</b>}<span>#{event.sequence}</span></header>
    <div>{stages.map((stage, index) => <div className={active.includes(index) ? "active" : ""} key={`${stage}-${index}`}><i /><span>{stage}</span>{index < stages.length - 1 && <ArrowRight size={14} />}</div>)}</div>
  </div>;
}

function NetworkMap({ data, liveEvent, stream }) {
  const overview = data?.overview || {};
  const machines = overview.machines || [];
  const jobs = data?.jobs || [];
  const units = jobs.flatMap((job) => job.work_units || []);
  const statuses = overview.operational_statuses || {};
  const projects = new Set(jobs.map((job) => job.project_id));
  const atomicItems = jobs.reduce((sum, job) => sum + Number(job.atomic_item_count || 0), 0);
  const plannedJobs = jobs.filter((job) => job.partition_plan_id).length;
  const activeJobs = jobs.filter((job) => ["queued", "running", "failed_retriable"].includes(job.status)).length;
  const inFlightUnits = units.filter((unit) => ["assigned", "running", "collecting"].includes(unit.status)).length;
  const collectingUnits = units.filter((unit) => unit.status === "collecting").length;
  const completedUnits = units.filter((unit) => unit.status === "completed").length;
  const liveMachines = machines.filter((machine) => statuses[machine.machine_id]?.telemetry_state === "live").length;
  const dispatcher = data?.dispatcher || {};
  const flowNodes = [
    { icon: Workflow, title: "Workbench", status: "active", value: `${projects.size} 个项目`, detail: `${jobs.length} 个 Job 记录` },
    { icon: Boxes, title: "Partition Planner", status: "active", value: `${plannedJobs} 个 v2 计划`, detail: `${atomicItems} 个原子项` },
    { icon: Database, title: "Control Plane", status: "online", value: `${liveMachines} / ${machines.length} 节点实时`, detail: `${activeJobs} 个活跃 Job` },
    { icon: MonitorCog, title: "Dispatcher", status: dispatcher.phase || "unknown", value: `${inFlightUnits} 个在途 Unit`, detail: dispatcher.lease ? "持有调度租约" : "当前无租约" },
  ];
  const flowEvent = liveEvent && ["work_unit.assigned", "work_unit.started", "work_unit.completed", "work_unit.retried", "work_unit.failed", "attempt.submitted", "attempt.collected", "machine.pressure_changed", "machine.pressure_override_confirmed", "dispatcher.cycle_failed", "partition_plan.created", "partition_plan.confirmed", "job.submitted"].includes(liveEvent.event_type);
  return <main className="app-page"><PageTitle eyebrow="NETWORK / LIVE TOPOLOGY" title="网络拓扑" detail="从任务定义到已登记机器执行与结果回收的实时全景" actions={<HelpLink topic="topology" />} />
    {stream === "connected" && flowEvent && <EventPath event={liveEvent} />}
    <section className="topology-band"><div className="section-heading"><div><h2>控制流</h2><span>组件结构固定，计数与状态来自正式 API</span></div></div>
      <div className="topology-control-flow">{flowNodes.map((node, index) => <div className="topology-flow-item" key={node.title}>
        <article className="topology-node"><header><node.icon size={18} /><Status value={node.status} /></header><h3>{node.title}</h3><strong>{node.value}</strong><small>{node.detail}</small></article>
        {index < flowNodes.length - 1 && <ArrowRight className="topology-arrow horizontal" size={20} />}
      </div>)}</div>
      <div className="topology-down"><ArrowDown size={20} /><span>资格匹配与公平领取</span></div>
    </section>
    <section className="topology-band"><div className="section-heading"><div><h2>登记执行节点</h2><span>{machines.length} 台当前环境登记机器</span></div><Status value={liveMachines === machines.length ? "live" : "stale"} /></div>
      <div className="topology-machine-grid">{machines.map((machine) => {
        const runtime = statuses[machine.machine_id] || {};
        const gpu = gpuDisplay(machine);
        const memoryPercent = machine.total_memory_mb ? machine.metrics?.memory_used_mb / machine.total_memory_mb * 100 : 0;
        const solver = (machine.capabilities || []).includes("solver-cudss") ? "cuDSS / MUMPS" : "MUMPS";
        const telemetryLive = runtime.telemetry_state === "live";
        const hasMetrics = Boolean(machine.metrics?.observed_at);
        const machineEvent = liveEvent?.subject_id === machine.machine_id || liveEvent?.details?.machine_id === machine.machine_id;
        return <Link to={`/app/machines/${machine.machine_id}`} className={`topology-machine ${machineEvent ? "event-flash" : ""}`} key={machine.machine_id}><header><div><Server size={17} /><b>{machine.display_name || machine.machine_id}</b></div><MachineHealth machine={machine} runtime={runtime} /></header>
          <div className="topology-machine-meta"><span>{solver}</span><small>{machine.total_cpus || 0} 线程 · {Math.round((machine.total_memory_mb || 0) / 1024)} GiB</small></div>
          <div className="topology-resources"><Resource value={machine.metrics?.cpu_total_percent} kind="cpu" inactive={!hasMetrics} frozen={hasMetrics && !telemetryLive} detail="CPU" /><Resource value={gpu.value} kind="gpu" inactive={gpu.inactive} frozen={!gpu.inactive && !telemetryLive} detail={gpu.inactive ? gpu.detail : "GPU"} /><Resource value={memoryPercent} kind="memory" inactive={!hasMetrics} frozen={hasMetrics && !telemetryLive} detail="内存" /></div>
          <footer><span>{machine.metrics?.running_units || 0} 个 Network Unit</span><span>指标于 {formatAge(metricTimestamp(machine, runtime))}</span></footer>
        </Link>;
      })}</div>
    </section>
    <section className="topology-band result-flow"><div className="section-heading"><div><h2>结果回流</h2><span>只有完成 origin staging 完整性校验的 Unit 才进入 completed</span></div></div>
      <div className="topology-result-flow"><article><Server size={18} /><div><b>执行节点</b><span>{inFlightUnits} 个在途 Unit</span></div></article><ArrowRight size={20} /><article><Database size={18} /><div><b>Origin staging</b><span>{collectingUnits} 个正在回收</span></div></article><ArrowRight size={20} /><article><CheckCircle2 size={18} /><div><b>Workbench collect</b><span>{completedUnits} 个已完整回收</span></div></article></div>
    </section>
  </main>;
}

const DISMISS_KEY = "rcn-runs-dismissed";
const DISMISS_LIMIT = 500;
function loadDismissedJobs() {
  try {
    const parsed = JSON.parse(localStorage.getItem(DISMISS_KEY) || "[]");
    return Array.isArray(parsed) ? parsed.filter((item) => typeof item === "string") : [];
  } catch {
    return [];
  }
}
function persistDismissedJobs(jobIds) {
  try { localStorage.setItem(DISMISS_KEY, JSON.stringify(jobIds)); } catch { /* private mode: session-only retention */ }
}

// Clock ticks and SSE bookkeeping re-render the app shell every second; the
// Runs table (145+ rows) must not reconcile on those renders. Memo keeps this
// subtree idle unless its own data, live event, or refresh identity changes.
const Runs = memo(function Runs({ data, liveEvent, refresh, loadMore }) {
  const jobsLoaded = Array.isArray(data?.jobs);
  const allJobs = jobsLoaded ? data.jobs : [];
  const machines = data?.overview?.machines || [];
  const admin = (data?.me?.roles || []).includes("admin");
  const [params, setParams] = useSearchParams();
  const query = params.get("q") || "";
  // The API returns both active and completed Workbench submissions. Showing
  // all records by default prevents short-lived jobs from disappearing before
  // an operator opens Runs; the queue board still isolates active work above.
  const status = params.get("status") || "all";
  const project = params.get("project") || "";
  const jobs = useMemo(() => project ? allJobs.filter(job => job.project_id === project) : allJobs, [allJobs, project]);
  const selected = jobs.find((job) => job.job_id === params.get("drawer")) || null;
  const reassignUnitId = params.get("reassign") || "";
  const [dismissedJobs, setDismissedJobs] = useState(loadDismissedJobs);
  const [pinnedJobId, setPinnedJobId] = useState("");
  const dismissJob = useCallback((jobId) => {
    setPinnedJobId((current) => (current === jobId ? "" : current));
    setDismissedJobs((current) => {
      const next = current.includes(jobId) ? current : [...current, jobId].slice(-DISMISS_LIMIT);
      persistDismissedJobs(next);
      return next;
    });
  }, []);
  const togglePinnedJob = useCallback((jobId) => setPinnedJobId((current) => current === jobId ? "" : jobId), []);
  const restoreDismissed = () => setDismissedJobs(() => {
    try { localStorage.removeItem(DISMISS_KEY); } catch { /* ignore */ }
    return [];
  });
  const restoreJob = (jobId) => setDismissedJobs((current) => {
    const next = current.filter((id) => id !== jobId);
    persistDismissedJobs(next);
    return next;
  });
  const closeAllFinished = (visibleJobIds) => setDismissedJobs((current) => {
    const next = [...new Set([...current, ...visibleJobIds])].slice(-DISMISS_LIMIT);
    persistDismissedJobs(next);
    return next;
  });
  // A pinned card keeps its action strip visible after the pointer leaves;
  // pressing anywhere outside the pinned card releases it again.
  useEffect(() => {
    if (!pinnedJobId) return;
    const onPointerDown = (event) => {
      const card = event.target instanceof Element ? event.target.closest(".finished-job") : null;
      if (!card || card.dataset.jobId !== pinnedJobId) setPinnedJobId("");
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [pinnedJobId]);
  // Finished jobs stay on the board until the operator closes them; the
  // dismissal lives in this browser's localStorage.
  const finishedJobs = useMemo(
    () => jobs.filter((job) => job.activity_state === "history" && !dismissedJobs.includes(job.job_id)),
    [jobs, dismissedJobs],
  );
  const dismissedRecords = useMemo(
    () => dismissedJobs
      .map((id) => jobs.find((job) => job.job_id === id))
      .filter(Boolean),
    [jobs, dismissedJobs],
  );
  const updateParams = useCallback((updates) => { const next = new URLSearchParams(params); Object.entries(updates).forEach(([key, value]) => value && value !== "all" ? next.set(key, value) : next.delete(key)); setParams(next); }, [params, setParams]);
  const openFinishedJob = useCallback((jobId) => updateParams({ drawer: jobId, unit: "" }), [updateParams]);
  const selectProject = useCallback((id) => updateParams({ project: id, drawer: "", unit: "" }), [updateParams]);
  const category = (job) => ["active", "queued"].includes(job.activity_state) ? "current" : ["recoverable", "needs_attention"].includes(job.activity_state) ? "attention" : "history";
  const filtered = useMemo(() => jobs.filter((job) => (status === "all" || category(job) === status) && `${job.job_id} ${job.project_id} ${job.user_id} ${job.origin_adapter_id || ""} ${job.execution_profile_id || ""}`.toLowerCase().includes(query.toLowerCase())), [jobs, query, status]);
  const activeJobs = jobs.filter((job) => ["active", "queued"].includes(job.activity_state));
  const actions = <div className="filter-row"><label className="search"><Search size={16} /><input value={query} onChange={(e) => updateParams({ q: e.target.value })} placeholder="搜索任务、项目或提交者" /></label><label className="select"><Filter size={15} /><select value={status} onChange={(e) => updateParams({ status: e.target.value })}><option value="current">当前运行</option><option value="attention">需要处理</option><option value="history">历史记录</option><option value="all">全部记录</option></select></label></div>;
  return <main className="app-page"><PageTitle eyebrow="RUNS / ATTEMPT LEDGER" title="任务运行" detail="按 Job、WorkUnit 和 attempt 追踪真实执行状态" actions={<><HelpLink topic="lifecycle" />{actions}</>} />
    <p className="fleet-scope-note">提交新任务请使用 RCN 成员客户端，导入项目侧 Workbench 准备的任务包。</p>
    <Suspense fallback={<DataLoadState compact label="正在加载集群工作摘要" />}><ClusterInsights compact selectedProject={project} onProjectSelect={selectProject} /></Suspense>
    {project && <p className="fleet-scope-note">当前任务列表按项目 <b>{project}</b> 筛选已加载的记录；加载范围见下方运行记录。效能摘要独立读取全量范围。</p>}
    {activeJobs.length > 0 && <><section className="queue-board"><div className="section-heading"><div><h2>公平队列与总体进度</h2><span>同优先级 Job 轮转领取共享池中的 WorkUnit</span></div></div><div className="queue-jobs">{activeJobs.map((job) => <JobProgress key={job.job_id} job={job} focused={liveEvent?.subject_id === job.job_id || liveEvent?.details?.job_id === job.job_id} onOpen={() => updateParams({ drawer: job.job_id, unit: "" })} />)}</div></section>
    <FleetLanes jobs={activeJobs} machines={machines} statuses={data?.overview?.operational_statuses || {}} liveEvent={liveEvent} admin={admin} onReassignUnit={(unit) => updateParams({ drawer: unit.job_id, reassign: unit.work_unit_id, unit: "" })} onOpenUnit={(unit) => updateParams({ drawer: unit.job_id, unit: unit.work_unit_id })} /></>}
    {(finishedJobs.length > 0 || dismissedJobs.length > 0) && <section className="queue-board finished-board"><div className="section-heading"><div><h2>已完成 · 保留在面板</h2><span>悬浮或点击卡片滑出操作条；点击卡片可固定，点击卡片外收起</span></div><span className="pool-count">{finishedJobs.length} 个{dismissedJobs.length ? ` · 已关闭 ${dismissedJobs.length}` : ""}</span>{finishedJobs.length > 0 && <button className="button small" title="关闭当前全部已完成卡片（可在已关闭列表单张或全部找回）" onClick={() => { setPinnedJobId(""); closeAllFinished(finishedJobs.map((job) => job.job_id)); }}><X size={14} />一键关闭</button>}</div>{finishedJobs.length > 0 && <div className="queue-jobs">{finishedJobs.map((job) => <FinishedJobCard key={job.job_id} job={job} pinned={pinnedJobId === job.job_id} onOpen={openFinishedJob} onDismiss={dismissJob} onTogglePin={togglePinnedJob} />)}</div>}{dismissedJobs.length > 0 && <RemovedTray records={dismissedRecords} onRestore={restoreJob} onRestoreAll={restoreDismissed} />}</section>}
    <section className="data-section">
      <div className="section-heading"><div><h2>运行记录</h2><span title={data?.jobsLoad?.error || undefined}>{jobsLoaded ? `${filtered.length} / ${jobs.length} 条 · ` : ""}{jobsLoadRangeText(data?.jobsLoad)}{data?.jobsUpdatedAt && ` · 更新 ${formatTime(data.jobsUpdatedAt)}`}</span></div>{data?.jobsLoad?.hasMore && <button className="button small" disabled={data.jobsLoad.status === "loading"} onClick={loadMore}>加载更多（50 条）</button>}</div>
      <div className="table-wrap">{!jobsLoaded ? <DataLoadState label="正在加载运行记录" error={data?.jobsLoad?.error} onRetry={refresh} /> : <><table><thead><tr><th>Job</th><th>项目 / 来源</th><th>状态 / Profile</th><th>流程 / ETA</th><th>工作单元</th><th>请求 / 执行合同</th><th>提示 / 阻塞</th><th>优先级</th><th /></tr></thead><tbody>{filtered.map((job) => {
        const completed = job.completed_unit_count ?? (job.work_units || []).filter((unit) => unit.status === "completed").length;
        const total = job.unit_count ?? (job.work_units || []).length;
        const timing = jobEta(job);
        const blockers = job.blocking_reasons || job.execution_environment?.reason_codes || [];
        const failures = job.failure_reasons || [];
        const effectivePriority = job.effective_priority ?? job.priority ?? 0;
        const priorityCeiling = job.priority_ceiling_snapshot;
        const requested = job.resource_summary || job.work_units?.[0]?.resources || {};
        const effective = job.effective_resource_summary;
        const actualCpu = effective ? resourceRange(effective, "cpus") : null;
        const effectiveSolvers = (effective?.solvers || []).join("/") || "-";
        return <tr key={job.job_id}>
          <td>{job.work_units?.length || !job.unit_count ? <button className="row-primary" onClick={() => updateParams({ drawer: job.job_id })}><b>{job.job_id}</b><small>{formatTime(job.created_at)}</small></button> : <Link className="row-primary" to={`/app/runs/${job.job_id}`}><b>{job.job_id}</b><small>{formatTime(job.created_at)}</small></Link>}</td>
          <td><b>{job.project_id}</b><small className="cell-sub">{job.origin_adapter_id || "legacy"} · {job.user_id}</small></td>
          <td><Status {...jobStatusPresentation(job)} /><small className="cell-sub" title={job.execution_profile_id}>{job.execution_profile_id || "未登记 Profile"}</small><small className="cell-sub">{jobEnvironmentLabel(job)}</small></td>
          <td><b>{jobPhaseLabel(job)}</b><small className="cell-sub">剩余 {timing.label}</small>{timing.at && <small className="cell-sub">完成 {formatTime(timing.at)}</small>}{timing.seconds != null && job.eta_updated_at && <small className="cell-sub">估计更新 {formatTime(job.eta_updated_at)}</small>}</td>
          <td>{completed} / {total}<small className="cell-sub">已完成</small></td>
          <td><b>请求 {requested.cpus ?? "-"} CPU</b><small className="cell-sub">{count(requested.memory_mb)} MiB</small>{effective ? <><small className="cell-sub" title={`冻结资源来源：${(effective.sources || []).join(", ")}`}>执行 {actualCpu} CPU · {effectiveSolvers}</small><small className="cell-sub">{effective.active_attempt_count} 个活动 Attempt</small></> : <small className="cell-sub">执行资源尚未冻结</small>}</td>
          <td>{job.planning_warnings?.length ? <Link className="warning-summary" title="打开 Job 详情查看计划警告" to={`/app/runs/${job.job_id}`}>{job.planning_warnings.length} 条 warning</Link> : <small className="cell-sub">无计划警告</small>}{blockers.length > 0 && <Link className="warning-summary" title={blockers.join("；")} to={`/app/runs/${job.job_id}`}>{blockers.length} 项待满足</Link>}{!blockers.length && failures.length > 0 && <Link className="warning-summary" title={failures.join("；")} to={`/app/runs/${job.job_id}`}>{job.failed_unit_count || 1} 个 Unit 失败</Link>}</td>
          <td><b>{effectivePriority} / {priorityCeiling ?? "-"}</b><small className="cell-sub">实际 / 项目上限</small>{job.priority !== effectivePriority && <small className="cell-sub">请求 {job.priority}</small>}</td>
          <td><Link className="icon-button" title="打开完整 Job 详情" to={`/app/runs/${job.job_id}`}><ChevronRight size={17} /></Link></td>
        </tr>;
      })}</tbody></table>{!filtered.length && <Empty icon={Boxes} text="没有匹配的运行记录" />}</>}</div>
    </section>
    {selected && data?.me?.actor_id && <JobDrawer key={`${data.me.actor_id}:${selected.job_id}`} actorId={data.me.actor_id} job={selected} machines={machines} admin={admin} refresh={refresh} onUpdated={() => refresh()} initialReassignUnitId={reassignUnitId} highlightUnitId={params.get("unit") || ""} onClose={() => updateParams({ drawer: "", reassign: "", unit: "" })} />}
  </main>;
});

function solverFor(unit) {
  return unit.attempts?.at(-1)?.solver_variant || [...(unit.allowed_solver_variants || [])].join("/") || "mumps";
}

const jobPhases = ["queued", "prepared", "assigned", "running", "finalizing", "collecting", "completed"];
function PhasePipeline({ phase, status }) {
  const phaseIndex = Math.max(0, jobPhases.indexOf(phase));
  const blocked = ["failed_retriable", "failed_terminal", "awaiting_approval", "blocked"].includes(status);
  return <div className="phase-pipeline" aria-label={`当前阶段 ${label(phase)}`}>{jobPhases.map((item, index) => <span className={`${index < phaseIndex || phase === "completed" ? "done" : ""}${item === phase ? " current" : ""}${blocked && item === phase ? " blocked" : ""}`} key={item}><i />{label(item)}</span>)}</div>;
}

function UnitStageStrip({ units, phase }) {
  const order = ["queued", "prepared", "assigned", "running", "reconcile_pending", "finalizing", "collecting", "retry", "failed", "completed"];
  const buckets = {};
  for (const unit of units) {
    const activity = unit.activity_state;
    const stage = unitIsReconciling(unit) ? "reconcile_pending"
      : activity === "prepared" ? "prepared"
      : activity === "finalizing" ? "finalizing"
      : unit.status === "failed_retriable" ? "retry"
      : unit.status === "failed_terminal" ? "failed"
      : unit.status;
    if (stage === "cancelled") continue;
    buckets[stage] = (buckets[stage] || 0) + 1;
  }
  const chips = order.map((stage) => ({ stage, count: buckets[stage] || 0 })).filter((item) => item.count > 0);
  return <div className="stage-strip" aria-label={`单元阶段分布 ${chips.map((item) => `${label(item.stage)} ${item.count}`).join("、")}`}>{chips.map(({ stage, count }) => <span className={`stage-chip stage-${stage}${stage === phase ? " current" : ""}`} key={stage}><b>{count}</b>{label(stage)}</span>)}</div>;
}

const RemovedTray = memo(function RemovedTray({ records, onRestore, onRestoreAll }) {
  const [expanded, setExpanded] = useState(false);
  return <div className="removed-tray">
    <button className="removed-tray-head" onClick={() => setExpanded((value) => !value)}>
      {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      已移除 ({records.length}) — 点开可单张找回
    </button>
    {expanded && <div className="removed-list">
      {records.map((job) => <div className="removed-row" key={job.job_id}>
        <b>{job.job_id}</b>
        <small>{job.project_id} · 完成于 {formatTime(job.updated_at)}</small>
        <button className="button small" onClick={() => onRestore(job.job_id)}><ArchiveRestore size={13} />找回</button>
      </div>)}
      {records.length > 1 && <div className="removed-row removed-row-all">
        <button className="button small" onClick={onRestoreAll}><ArchiveRestore size={13} />全部找回</button>
      </div>}
    </div>}
  </div>;
});

const FinishedJobCard = memo(function FinishedJobCard({ job, pinned = false, onOpen, onDismiss, onTogglePin }) {  const completed = job.completed_unit_count ?? 0;
  const total = job.unit_count ?? 0;
  const percent = total > 0 ? Math.round(completed / total * 100) : 100;
  const unitsEmbedded = (job.work_units || []).length > 0;
  return <article
    className={`queue-job finished-job clickable${pinned ? " pinned" : ""}`}
    data-job-id={job.job_id}
    onClick={() => onTogglePin?.(job.job_id)}
    title={pinned ? "已固定操作条 · 点击卡片外取消固定" : "点击固定操作条（移开鼠标不消失）"}
  >
    <header><div><b>{job.job_id}</b><small>{job.project_id} · {jobEnvironmentLabel(job)}</small></div><Status {...jobStatusPresentation(job)} /></header>
    <div className="job-progress"><i style={{ width: `${percent}%` }} /></div>
    <div className="job-timing"><span>单元 {completed} / {total}</span>{job.total_elapsed_seconds != null && <span>耗时 {formatDuration(job.total_elapsed_seconds)}</span>}<span>完成于 {formatTime(job.updated_at)}</span></div>
    {!unitsEmbedded && <p className="finished-archived">单元明细已归档 · 打开历史记录查看完整 provenance</p>}
    {/* The action strip lives inside the card and slides in from the right;
        a click pins it so it survives the pointer leaving the card. */}
    <div className="finished-actions" onClick={(event) => event.stopPropagation()}>
      <Link className="finished-action" to={`/app/runs/${job.job_id}`}><ArchiveRestore size={13} />历史运行记录</Link>
      <button className="finished-action" onClick={() => onOpen?.(job.job_id)}><PanelRightOpen size={13} />详情抽屉</button>
      <button className="finished-action danger" title="从面板关闭（可随时恢复）" onClick={() => onDismiss?.(job.job_id)}><X size={13} />关闭</button>
    </div>
  </article>;
});

export const JobProgress = memo(function JobProgress({ job, focused = false, onOpen }) {
  const units = job.work_units || [];
  const { completed: atomsDone, total: atomTotal } = jobProgressTotals(job);
  const percent = atomTotal > 0 ? Math.round(atomsDone / atomTotal * 100) : 0;
  const solverCounts = Object.keys(job.solver_counts || {}).length ? job.solver_counts : units.reduce((result, unit) => ({ ...result, [solverFor(unit)]: (result[solverFor(unit)] || 0) + 1 }), {});
  const phase = currentJobPhase(job);
  const timing = jobEta(job);
  const elapsed = job.total_elapsed_seconds ?? job.elapsed_seconds;
  const blockers = job.blocking_reasons || job.execution_environment?.reason_codes || [];
  const retriable = units.filter((unit) => unit.status === "failed_retriable").length;
  const waitReasons = blockers.filter((reason) => reason.startsWith("项目并发"));
  const faultReasons = blockers.filter((reason) => !reason.startsWith("项目并发"));
  const shownReasons = (faultReasons.length ? faultReasons : waitReasons).slice(0, 2);
  const series = jobCompletionSeries(job);
  return <article className={`queue-job clickable ${focused ? "event-flash" : ""}`} onClick={() => onOpen?.()} title="点击打开详情抽屉"><header><div><b>{job.job_id}</b><small>{job.project_id} · {jobEnvironmentLabel(job)} · priority {job.priority || 0}</small></div><Status {...jobStatusPresentation(job)} /></header><UnitStageStrip units={units} phase={phase} /><div className="job-progress"><i style={{ width: `${percent}%` }} /></div><div className="job-timing"><span>已耗时 <b>{formatDuration(elapsed)}</b></span><span>预计剩余 <b>{timing.label}</b></span>{timing.at && <span>预计完成 <b>{formatTime(timing.at)}</b></span>}{series && <MiniSpark series={series} />}</div>{reconciliationNotice(job) && <p className="job-blocking wait">{reconciliationNotice(job)}</p>}{retriable > 0 && <p className="job-retrying" title="仅基础设施类故障（传输、超时、进程崩溃）会自动重试，耗尽有界次数才进入终态；科学计算错误不会重试。单元若在求解中途崩溃会重算该单元，已完成单元不受影响。">{retriable} 个 Unit 上次尝试未成功 · 自动重试中</p>}{shownReasons.length > 0 && <p className={`job-blocking${faultReasons.length ? "" : " wait"}`} title={blockers.join("；")}>{faultReasons.length > 0 ? "阻塞：" : "等待："}{shownReasons.join("；")}</p>}<footer><span>{atomTotal > 0 ? `${atomsDone} / ${atomTotal} 原子项` : `原子项计数同步中 · ${units.length} Units`}</span><span>{Object.entries(solverCounts).map(([solver, value]) => `${solver} ${value}`).join(" · ")}</span></footer></article>;
});

function FleetLanes({ jobs, machines, statuses = {}, liveEvent, admin = false, onReassignUnit = null, onOpenUnit = null }) {
  const records = fleetRecords(machines);
  const units = jobs.flatMap((job) => (job.work_units || []).map((unit) => ({ ...unit, job_id: job.job_id })));
  const jobEtaSeconds = Object.fromEntries(jobs.map((job) => [job.job_id, jobEta(job).seconds]));
  const waiting = units.filter((unit) => !unit.assigned_machine_id && ["queued", "failed_retriable"].includes(unit.status));
  return <section className="lane-board"><div className="section-heading"><div><h2>机器泳道</h2><span>staging、queued、running、collecting、completed 与 retry/migration</span></div><span className="pool-count">共享池 {waiting.length}</span></div><div className="lanes">
    {records.current.map((machine) => {
      const laneUnits = units.filter((unit) => unit.assigned_machine_id === machine.machine_id);
      const phase = statuses[machine.machine_id]?.heartbeat_phase || "offline";
      return <div className="machine-lane" key={machine.machine_id}><header><b>{machine.display_name || machine.machine_id}</b><Status value={phase === "healthy" ? "live" : phase} /></header><div>{laneUnits.map((unit) => <UnitChip key={`${unit.job_id}-${unit.work_unit_id}`} unit={unit} jobEtaSeconds={jobEtaSeconds[unit.job_id]} active={liveEvent?.subject_id === unit.work_unit_id} admin={admin} onReassignUnit={onReassignUnit} onOpenUnit={onOpenUnit} />)}{!laneUnits.length && <span className="lane-empty">空闲</span>}</div></div>;
    })}
    <div className="machine-lane shared-pool"><header><b>共享分配池</b><span>{waiting.length} Units</span></header><div>{waiting.map((unit) => <UnitChip key={`${unit.job_id}-${unit.work_unit_id}`} unit={unit} jobEtaSeconds={jobEtaSeconds[unit.job_id]} admin={admin} onReassignUnit={onReassignUnit} onOpenUnit={onOpenUnit} />)}{!waiting.length && <span className="lane-empty">队列为空</span>}</div></div>
  </div><FleetHistory records={records.historical} matches={records.historical} query="" /></section>;
}

const UnitChip = memo(function UnitChip({ unit, active = false, jobEtaSeconds = null, admin = false, onReassignUnit = null, onOpenUnit = null }) {
  const migrated = unit.attempts?.at(-1)?.migrated;
  const phase = unitIsReconciling(unit) ? "reconcile_pending" : unit.dispatch_phase || unit.status;
  const completed = Number(unit.completed_items || 0);
  const total = unitItemCount(unit);
  const progress = total ? ` · ${completed}/${total}` : "";
  const etaText = unitEtaLabel(unit, jobEtaSeconds);
  const title = [`所属 Job ${unit.job_id}`, unit.work_unit_id, label(phase), total ? `${completed}/${total} 原子项` : "", etaText, unit.progress_message, unit.failure_reason].filter(Boolean).join("\n");
  const showEta = ["assigned", "running", "finalizing", "collecting"].includes(unit.status);
  return <div className={`unit-chip unit-${unit.status} ${active ? "unit-event" : ""}${onOpenUnit ? " clickable" : ""}`} title={title} onClick={onOpenUnit ? () => onOpenUnit(unit) : undefined}><span className="chip-job">{unit.job_id.slice(-6)} / {String(unit.ordinal + 1).padStart(2, "0")}</span><small>{label(phase)}{progress} · {solverFor(unit)}{migrated ? " · migration" : ""}</small>{showEta && <em>{etaText}</em>}{admin && onReassignUnit && unitReassignable(unit) && <button className="chip-reassign" title="改派到其他机器（管理员）" onClick={(event) => { event.stopPropagation(); onReassignUnit(unit); }}><ArrowLeftRight size={11} /></button>}</div>;
});

export function JobDrawer({ actorId, job, machines, admin, refresh, onUpdated, onClose, initialReassignUnitId = "", highlightUnitId = "" }) {
  const transaction = useJobTransactions({ actorId, job, refresh, onUpdated });
  const { operation, setOperation, reason, setReason, ticket, busy, error: operationError, begin, preview: previewOperation, confirm: confirmOperation } = transaction;
  const [reassign, setReassign] = useState(transaction.reassignment ? { work_unit_id: transaction.reassignment.work_unit_id } : null);
  const [reassignTarget, setReassignTarget] = useState("");
  const [reassignReason, setReassignReason] = useState("");
  useEffect(() => {
    if (transaction.notice !== "原单元改派已完成。") return;
    setReassign(null); setReassignTarget(""); setReassignReason("");
  }, [transaction.notice]);
  const [placementRequest, setPlacementRequest] = useState({ jobId: job.job_id, status: "loading", error: "", data: null });
  const [placementReload, setPlacementReload] = useState(0);
  const needsPlacementDiagnostics = (job.work_units || []).some((unit) => unit.status === "queued" || unit.dispatch_phase === "prepared");
  useEffect(() => {
    if (!admin || !initialReassignUnitId || transaction.pendingTicket || transaction.reassignment) return;
    const unit = (job.work_units || []).find((item) => item.work_unit_id === initialReassignUnitId);
    if (unit && unitReassignable(unit)) {
      setReassign({ work_unit_id: initialReassignUnitId });
      setOperation(null);
    }
    // The URL parameter is consumed once; further panel control is local state.
  }, [admin, initialReassignUnitId, job.job_id]);
  useEffect(() => {
    let active = true;
    if (!needsPlacementDiagnostics) {
      setPlacementRequest({ jobId: job.job_id, status: "loaded", error: "", data: null });
      return () => { active = false; };
    }
    setPlacementRequest((current) => current.jobId === job.job_id && current.data
      ? { ...current, status: "refreshing", error: "" }
      : { jobId: job.job_id, status: "loading", error: "", data: null });
    api(`/v1/jobs/${job.job_id}/placement-diagnostics`)
      .then((value) => { if (active) setPlacementRequest({ jobId: job.job_id, status: "loaded", error: "", data: value }); })
      .catch((caught) => { if (active) setPlacementRequest((current) => ({ ...current, jobId: job.job_id, status: "error", error: caught.message })); });
    return () => { active = false; };
  }, [job.job_id, job.revision, needsPlacementDiagnostics, placementReload]);
  const placementDiagnostics = placementRequest.jobId === job.job_id ? placementRequest.data : null;
  const placementUnits = (placementDiagnostics?.units || []).filter((unit) => unit.status === "queued" || unit.dispatch_phase === "prepared");
  const cancelling = operation?.action?.startsWith("cancel");
  useEffect(() => {
    if (!highlightUnitId) return;
    const node = document.getElementById(`unit-row-${highlightUnitId}`);
    if (node) node.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [highlightUnitId, job.job_id]);
  const runReassign = (unitId) => transaction.submitReassignment((job.work_units || []).find((unit) => unit.work_unit_id === unitId), reassignTarget, reassignReason);
  const timing = jobEta(job);
  return <Drawer title={job.job_id} subtitle={`${job.project_id} · ${job.user_id}`} onClose={onClose}>
    <div className="drawer-status"><Status {...jobStatusPresentation(job)} /><Status value={currentJobPhase(job)} text={jobPhaseLabel(job)} /><span className="profile-chip">{job.execution_profile_id}</span><Link className="drawer-full-link" title="打开完整 Job 详情页（含科学载荷 provenance）" to={`/app/runs/${job.job_id}`} onClick={onClose}>完整详情 <ChevronRight size={14} /></Link></div>
    <Description rows={[["来源适配器", job.origin_adapter_id || "legacy"], ["来源提交者", job.origin_submitter_id], ["请求哈希", job.request_hash], ["PartitionPlan", job.partition_plan_id || "v1 预分组"], ["原子项", job.atomic_item_count ?? job.total_items ?? "未声明"], ["项目并发", job.project_concurrency_state === "not_requested" ? "历史记录按需检查" : job.project_concurrency?.max_running_units == null ? "未配置" : `${job.project_concurrency.active_units || 0} 运行 + ${job.project_concurrency.prepared_units || 0} 预备 / ${job.project_concurrency.max_running_units}`], ["请求 / 实际 / 上限 priority", `${job.priority ?? 0} / ${job.effective_priority ?? job.priority ?? 0} / ${job.priority_ceiling_snapshot ?? "-"}`], ["已耗时", formatDuration(job.total_elapsed_seconds)], ["预计剩余", timing.label], ["预计完成", timing.at ? formatTime(timing.at) : "暂无可靠估计"], ["最后事件", job.last_event_at ? formatTime(job.last_event_at) : formatTime(job.updated_at)], ["创建时间", formatTime(job.created_at)], ["更新时间", formatTime(job.updated_at)]]} />
    {job.execution_environment_state === "not_requested" && <JobExecutionConditions key={`${actorId}:${job.job_id}`} actorId={actorId} jobId={job.job_id} />}
    {reconciliationNotice(job) && <p className="job-blocking wait">{reconciliationNotice(job)}</p>}
    {(job.blocking_reasons || []).length > 0 && <section className="drawer-blocking"><h3>当前阻塞原因</h3><ul>{job.blocking_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></section>}
    {(job.failure_reasons || []).length > 0 && <section className="drawer-blocking"><h3>Unit 失败证据</h3><p>{job.failed_unit_count || 1} 个 Unit 已失败；其余可执行 Unit 不因此停滞。</p><ul>{job.failure_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></section>}
    {job.schema_version === 2 && <><h3>原子项分区预览</h3><div className="partition-preview">{(job.work_units || []).map((unit) => <div key={unit.work_unit_id} style={{ flexGrow: Math.max(1, unitItemCount(unit)) }}><b>U{unit.ordinal + 1}</b><span>{unitItemCount(unit)} 点</span></div>)}</div></>}
    <h3>完成轨迹</h3>
    <CompletionCurve series={jobCompletionSeries(job)} />
    <h3>工作单元时间线</h3><div className="timeline">{(() => {
      const drawerTimeWindow = jobTimeWindow(job);
      return (job.work_units || []).map((unit, index) => {
      const machine = machines.find((m) => m.machine_id === unit.assigned_machine_id);
      const attempt = unit.attempts?.at(-1);
      const canCancel = ["queued", "assigned", "running", "collecting", "failed_retriable"].includes(unit.status);
      const retryable = unit.status === "failed_retriable" || unit.recovery_allowed;
      const segments = attemptSegments(unit);
      return <div className={`timeline-item${unit.work_unit_id === highlightUnitId ? " unit-highlight" : ""}`} key={unit.work_unit_id} id={`unit-row-${unit.work_unit_id}`}><span>{String(index + 1).padStart(2, "0")}</span><div><b>{unit.work_unit_id}</b><small>{machine?.display_name || unit.assigned_machine_id || "尚未派发"} · {solverFor(unit)} · attempt {unit.attempt_count || 0}{attempt?.migrated ? " · migration" : ""}</small><small>{unitItemCount(unit) || "?"} 原子项 · {unit.completed_items || 0}/{unit.total_items || unitItemCount(unit) || "?"} · {unitEtaLabel(unit, timing.seconds)}</small>{segments.length > 0 && <AttemptTimeline segments={segments} window={drawerTimeWindow} />}{unit.progress_message && <small>{unit.progress_message}</small>}{unit.failure_reason && <em>{unit.failure_reason}</em>}{unit.recovery_reason && <small className="recovery-note">{unit.recovery_reason}</small>}<AbandonAttemptControl admin={admin} jobId={job.job_id} unit={unit} onCompleted={refresh} /></div><div className="timeline-actions"><Status value={unitIsReconciling(unit) ? "reconcile_pending" : unit.status} />{admin && retryable && <button className="icon-button" title="预览重试或迁移" disabled={transaction.locked} onClick={() => begin("retry_unit", unit.work_unit_id)}><RefreshCw size={14} /></button>}{admin && canCancel && <button className="icon-button" title="预览取消单元" disabled={transaction.locked} onClick={() => begin("cancel_unit", unit.work_unit_id)}><X size={14} /></button>}{admin && unitReassignable(unit) && <button className="icon-button" title="改派到其他机器" disabled={transaction.locked || Boolean(transaction.pendingTicket)} onClick={() => { setReassign({ work_unit_id: unit.work_unit_id }); setReassignTarget(""); setReassignReason(""); setOperation(null); }}><ArrowLeftRight size={14} /></button>}</div></div>;
      });
    })()}</div>
    {needsPlacementDiagnostics && <section className="placement-diagnostics"><div className="section-heading"><div><h3>等待与放置诊断</h3><span>资源、授权、运行时与队列条件</span></div><RefreshStatus visible={placementRequest.status === "refreshing"} label="正在刷新诊断" /></div>
      {placementRequest.status === "loading" && <DataLoadState compact label="正在计算放置条件" />}
      {placementRequest.status === "error" && !placementDiagnostics && <DataLoadState compact error={placementRequest.error} onRetry={() => setPlacementReload((value) => value + 1)} />}
      {placementUnits.map((unit) => <article key={unit.work_unit_id}><header><b>U{unit.ordinal + 1} · {unit.dispatch_phase === "prepared" ? "已预备" : `队列第 ${unit.queue_position || "-"} 位`}</b><span>{unit.eligible_machine_count} 台可立即执行</span></header><p>资源来源 {unit.resolved_resources?.source || "unknown"} · policy revision {unit.resolved_resources?.policy_revision || 1} · {unit.resolved_resources?.resources?.cpus || "-"} CPU · {unit.resolved_resources?.resources?.memory_mb || "-"} MiB 内存</p>{unit.blockers?.length > 0 && <ul>{unit.blockers.map((blocker) => <li key={`${blocker.code}-${blocker.message}`}><b>{blocker.code}</b><span>{blocker.message}</span></li>)}</ul>}</article>)}
      {placementRequest.status === "loaded" && !placementUnits.length && <p className="placement-diagnostics-empty">诊断已更新，当前没有等待放置的 Unit。</p>}
      {placementRequest.status === "error" && placementDiagnostics && <DataLoadState compact error={`诊断刷新失败：${placementRequest.error}`} onRetry={() => setPlacementReload((value) => value + 1)} />}
    </section>}
    {admin && <section className="drawer-control"><h3>管理员操作</h3><p>所有操作先生成绑定当前 Job revision 的预览票据；状态在确认前变化时，服务端会拒绝执行。</p><div className="admin-action-row">{!["completed", "cancelled", "failed_terminal"].includes(job.status) && <button className="button" disabled={transaction.locked} onClick={() => begin("cancel_job")}><X size={15} />取消 Job</button>}{job.status === "failed_retriable" && <button className="button" disabled={transaction.locked} onClick={() => begin("retry_job")}><RefreshCw size={15} />重试 Job</button>}</div>
      {operation && !ticket && <div className="operation-compose"><b>{operation.action}{operation.work_unit_id ? ` · ${operation.work_unit_id}` : ""}</b>{cancelling && <label>取消原因<input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="填写可审计原因" /></label>}<div><button className="button" disabled={busy} onClick={() => setOperation(null)}>关闭</button><button className="button button-primary" disabled={busy || (cancelling && !reason.trim())} onClick={previewOperation}>{busy ? <><RefreshCw size={15} className="spin" />正在生成</> : "生成预览"}</button></div></div>}
      {ticket && <div className="control-preview"><Description rows={[["操作", ticket.action], ["影响单元", ticket.impact?.affected_units], ["当前状态", ticket.impact?.unit_status || ticket.impact?.job_status], ["票据过期", formatTime(ticket.expires_at)], ["原因", ticket.reason || "不适用"]]} /><div><button className="button" disabled={busy || transaction.pendingTicket?.submitted} onClick={transaction.editTicket}>返回修改</button>{transaction.pendingTicket?.submitted && <button className="button" disabled={busy} onClick={transaction.recoverTicket}>核对原操作结果</button>}<button className="button button-primary" disabled={busy} onClick={confirmOperation}>{busy ? <><RefreshCw size={15} className="spin" />正在执行</> : <><CheckCircle2 size={16} />{transaction.pendingTicket?.submitted ? "重试原票据" : "确认执行"}</>}</button></div></div>}
      {transaction.pendingTicket?.submitted && <p role="status">原票据已提交，离页后仍保留；恢复只查询原结果，重试仍使用同一票据。</p>}
      {transaction.notice && <p role="status">{transaction.notice}</p>}
      {operationError && <div className="form-error">{operationError}</div>}
    </section>}
    {admin && (reassign || transaction.reassignment) && (() => {
      const pending = transaction.reassignment;
      const unit = (job.work_units || []).find((item) => item.work_unit_id === (pending?.work_unit_id || reassign.work_unit_id));
      if (!unit) return null;
      const durations = jobMachineDurations(job);
      const currentMachine = unit.assigned_machine_id || unit.attempts?.at(-1)?.machine_id || "";
      const candidates = machines.filter((machine) => machine.machine_id !== currentMachine || machine.machine_id === pending?.body.target_machine_id);
      const measured = (machineId) => {
        const entry = durations[machineId];
        return entry
          ? `本 Job ${entry.count} 个单元实测 · 平均 ${Math.round(entry.totalMinutes / entry.count)} 分 · 最长 ${Math.round(entry.maxMinutes)} 分`
          : "本 Job 暂无该机实测记录";
      };
      return <section className="drawer-control reassign-panel"><h3>改派单元 U{unit.ordinal + 1}</h3>
        <p>当前机器 {currentMachine || "共享池（尚未派发）"} · {measured(currentMachine)}。改派将把该单元固定到目标机执行：运行中的单元先取消传播，再自动重试到目标机；已完成单元不受影响，不会重复计算。</p>
        <label>目标机器<select disabled={busy || Boolean(pending)} value={pending?.body.target_machine_id || reassignTarget} onChange={(event) => setReassignTarget(event.target.value)}><option value="">选择目标机器…</option>{candidates.map((machine) => <option key={machine.machine_id} value={machine.machine_id}>{machine.display_name || machine.machine_id}（运行中 {machine.metrics?.running_units || 0}）</option>)}</select></label>
        {reassignTarget && <p className="reassign-cost">目标机实测：{measured(reassignTarget)}</p>}
        <label>改派原因（审计必填）<input disabled={busy || Boolean(pending)} value={pending?.body.reason || reassignReason} onChange={(event) => setReassignReason(event.target.value)} placeholder="例如：目标机实测更快；当前机需腾挪" /></label>
        {pending && <p role="status">原改派 {pending.body.operation_id} · 原尝试 {pending.body.expected_attempt_id || "尚未派发"} · {pending.stage === "cancel_requested" ? "等待取消传播，尚未完成" : "结果待核对"}。刷新或离页后仍保留同一请求。</p>}
        {operationError && <div className="form-error">{operationError}</div>}
        <div><button className="button" disabled={busy || Boolean(pending)} onClick={() => setReassign(null)}>关闭</button>{pending && <button className="button" disabled={busy} onClick={transaction.recoverReassignment}>核对原改派</button>}<button className="button button-primary" disabled={busy || (!pending && (!reassignTarget || !reassignReason.trim()))} onClick={() => runReassign(unit.work_unit_id)}>{busy ? <><RefreshCw size={15} className="spin" />改派中…</> : pending ? "继续原改派" : "确认改派"}</button></div>
      </section>;
    })()}
  </Drawer>;
}

function Operations({ data, refresh, eventTrail = [] }) {
  const overview = data?.overview || {};
  const dispatcher = data?.dispatcher || {};
  const metrics = data?.metrics || {};
  const admin = (data?.me?.roles || []).includes("admin");
  return <main className="app-page"><PageTitle eyebrow="OPERATIONS / CONTROL PLANE" title="运营与审计" detail="Dispatcher 租约、投递异常、系统容量和最近事件" actions={<><HelpLink topic="dispatcher" /><button className="button" onClick={refresh}><RefreshCw size={16} />刷新状态</button></>} />
    <div className="metric-strip"><Metric icon={Activity} label="运行任务" value={count(overview.summary?.running_jobs)} detail={`${count(overview.summary?.queued_jobs)} 个排队`} /><Metric icon={Clock3} label="待 reconcile" value={count(metrics.pending_reconciliation)} detail="不确定或待核对 attempt" tone={metrics.pending_reconciliation ? "warn" : "good"} /><Metric icon={Gauge} label="成功率" value={`${Math.round((metrics.completed_jobs || 0) / Math.max(1, metrics.total_jobs || 0) * 100)}%`} detail={`${count(metrics.total_jobs)} 个总任务`} /><Metric icon={Database} label="数据边界" value="Metadata" detail={`协议 ${dispatcher.protocol_version || "1"}`} /></div>
    <div className="operations-layout"><section className="data-section dispatcher-panel"><div className="section-heading"><div><h2>Dispatcher</h2><span>单实例租约与 reconcile 状态</span></div><Status value={dispatcher.state || "standby"} /></div>
      <Description rows={[["Owner ID", dispatcher.owner_id || "未持有"], ["租约到期", formatTime(dispatcher.lease?.expires_at)], ["最近 reconcile", formatTime(dispatcher.last_reconcile_at)], ["活跃投递", dispatcher.active_assignments || 0], ["package", dispatcher.package_version || "0.4.0"], ["runtime", dispatcher.runtime_version || "-"]]} />
      <div className="operation-note"><ShieldCheck size={17} /><span>启动新 Dispatcher 前必须确认旧租约已释放，并先执行 reconcile。页面不提供跳过该边界的快捷操作。</span></div>
    </section><section className="data-section"><div className="section-heading"><div><h2>活动告警</h2><span>{(overview.alerts || []).length} 条</span></div></div><div className="alert-list">{(overview.alerts || []).map((alert, i) => <div key={`${alert.machine_id}-${i}`}><AlertTriangle size={16} /><span><b>{alert.machine_id}</b><small>{label(alert.kind)} · {label(alert.message)}</small></span></div>)}{!(overview.alerts || []).length && <Empty icon={CheckCircle2} text="当前没有活动告警" compact />}</div></section></div>
    <section className="data-section event-section"><div className="section-heading"><div><h2>最近审计事件</h2><span>{admin ? "管理员全局视图" : "按权限过滤"}</span></div></div><div className="event-list">{[...eventTrail, ...(overview.recent_events || [])].filter((event, index, list) => list.findIndex((item) => item.event_id === event.event_id) === index).slice(0, 80).map((event) => { const target = eventTarget(event); return <div key={event.event_id}><span className="event-dot" /><time>{formatTime(event.created_at)}</time><b>{event.event_type}</b><span>{event.details?.reason || event.details?.error || event.actor_id}</span>{target ? <Link to={target}><code>{event.subject_id}</code></Link> : <code>{event.subject_id}</code>}</div>; })}</div></section>
  </main>;
}

function Drawer({ title, subtitle, onClose, children }) {
  return <><button className="drawer-backdrop" aria-label="关闭详情" onClick={onClose} /><aside className="drawer"><header><div><span>DETAIL</span><h2>{title}</h2><p>{subtitle}</p></div><button className="icon-button" title="关闭" onClick={onClose}><X size={19} /></button></header>{children}</aside></>;
}
function Description({ rows }) { return <dl className="description">{rows.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{String(value ?? "-")}</dd></div>)}</dl>; }
function Empty({ icon: Icon, text, compact = false }) { return <div className={`empty ${compact ? "compact" : ""}`}><Icon size={20} /><span>{text}</span></div>; }
function Loading({ full = false }) { return <div className={`loading ${full ? "full" : ""}`}><RefreshCw size={20} className="spin" /><span>正在读取状态</span></div>; }
function ErrorState({ message }) { return <div className="error-state"><AlertTriangle size={22} /><h2>内容暂时不可用</h2><p>{message}</p></div>; }

export default function App() {
  const [client, setClient] = useState(undefined);
  const [bootError, setBootError] = useState("");
  const [bootRevision, setBootRevision] = useState(0);
  useEffect(() => {
    let active = true;
    setBootError("");
    const controller = new AbortController();
    detectMemberClient({ signal: controller.signal }).then((capabilities) => { if (active) setClient(capabilities); })
      .catch((error) => { if (active) setBootError(error.message); });
    return () => { active = false; controller.abort(); };
  }, [bootRevision]);
  if (bootError) return <main className="connect-main"><section><h1>客户端暂时无法连接</h1><p role="alert">{bootError}</p><button className="button" onClick={() => setBootRevision((value) => value + 1)}>重新连接</button></section></main>;
  if (client === undefined) return <Loading full />;
  if (client) return <BrowserRouter><HelpProvider><Suspense fallback={<Loading full />}><MemberClient capabilities={client} /></Suspense></HelpProvider></BrowserRouter>;
  return <BrowserRouter><HelpProvider><Routes>
    <Route path="/" element={<Navigate to="/help" replace />} />
    <Route path="/help" element={<HelpCenter />} />
    <Route path="/help/overview" element={<Navigate to="/help" replace />} />
    <Route path="/help/:slug" element={<HelpCenter />} />
    <Route path="/connect" element={<Connect />} />
    <Route path="/app/*" element={<AppShell />} />
    <Route path="*" element={<Navigate to="/help" replace />} />
  </Routes></HelpProvider></BrowserRouter>;
}

function resourceRange(summary, field) {
  const minimum = summary?.[`${field}_min`];
  const maximum = summary?.[`${field}_max`];
  if (minimum == null || maximum == null) return "-";
  return minimum === maximum ? String(minimum) : `${minimum}–${maximum}`;
}
