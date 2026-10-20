import { useEffect, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, ShieldAlert, X } from "lucide-react";

import { api } from "./api";
import { confirmControlTicket, controlRunByTicket } from "./controlConfirmation";
import { clearControlCheckpoint, controlCheckpoint, controlResumeBody, controlScope, loadControlCheckpoint, saveControlCheckpoint, validateControlScope } from "./controlCheckpoint";

function useControlRequest(scope, onRestore, onClose, onComplete) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [uncertain, setUncertain] = useState(false);
  const [actorId, setActorId] = useState("");
  const [identityRetry, setIdentityRetry] = useState(0);
  const inFlight = useRef(false), checkpoint = useRef(null), accepted = useRef(null), alive = useRef(true);
  const restore = useRef(onRestore); restore.current = onRestore;
  const scopeKey = JSON.stringify(scope);
  const execute = async (work) => {
    if (inFlight.current) return;
    inFlight.current = true; setBusy(true); setError("");
    try { await work(); }
    catch (caught) { if (alive.current) setError(caught.message); }
    finally { inFlight.current = false; if (alive.current) setBusy(false); }
  };
  const finish = async (result) => {
    validateControlScope(result, checkpoint.current); accepted.current = result;
    if (!alive.current) return;
    try { await onComplete?.(result); }
    catch (caught) { throw new Error(`操作 ${result.operation_id} 已被接受；页面刷新失败：${caught.message}。再次确认只核对原操作。`); }
    if (alive.current) { clearControlCheckpoint(sessionStorage, checkpoint.current); checkpoint.current = null; setUncertain(false); onClose(); }
  };
  const recoverValue = (value) => execute(async () => {
    try { await finish(accepted.current || await controlRunByTicket(api, value.body.ticket_id)); }
    catch (caught) { throw new Error(`原票据结果仍未确认：${caught.message}。原身份、范围和票据已保留；恢复只查询原结果。`); }
  });
  useEffect(() => {
    alive.current = true;
    const controller = new AbortController(); let current = true;
    setActorId(""); setError("");
    (async () => {
      try {
        const me = await api("/v1/me", { signal: controller.signal });
        if (!current) return;
        if (!me?.actor_id) throw new Error("尚未读取到操作者身份，不能预览或确认。");
        const value = loadControlCheckpoint(sessionStorage, me.actor_id, scope);
        setActorId(me.actor_id); checkpoint.current = value;
        if (value) { setUncertain(true); restore.current(value.ticket); await recoverValue(value); }
      } catch (caught) { if (current) setError(caught.message); }
    })();
    return () => { current = false; alive.current = false; controller.abort(); };
  }, [scopeKey, identityRetry]);
  const confirm = (path, body, ticket) => execute(async () => {
    if (!actorId) throw new Error("请先读取操作者身份。");
    const value = checkpoint.current || controlCheckpoint(actorId, scope, ticket, body);
    checkpoint.current = saveControlCheckpoint(sessionStorage, value);
    setUncertain(true);
    try {
      const requestBody = controlResumeBody(checkpoint.current, body);
      const result = accepted.current || await confirmControlTicket(api, path, requestBody, { recoverFirst: uncertain });
      await finish(result);
    } catch (caught) {
      const rejected = [400, 404, 409, 410, 422].includes(caught.status);
      if (!accepted.current && alive.current && rejected) {
        clearControlCheckpoint(sessionStorage, checkpoint.current); checkpoint.current = null; setUncertain(false);
      }
      throw new Error(`${caught.message}${accepted.current || rejected ? "" : "。结果尚未确认，原票据已保留；可核对结果或显式重试同一票据。"}`);
    }
  });
  const recover = () => checkpoint.current && recoverValue(checkpoint.current);
  const preview = (work) => execute(async () => {
    if (!actorId || checkpoint.current) throw new Error("请先核对当前身份及原控制操作，不能生成替代预览。");
    accepted.current = null; setUncertain(false); await work();
  });
  return { busy, error, ready: Boolean(actorId), execute, preview, confirm, recover, locked: uncertain || accepted.current != null,
    recovery: uncertain ? <button className="button" disabled={busy} onClick={recover}>核对原票据结果</button>
      : !actorId && error ? <button className="button" disabled={busy} onClick={() => setIdentityRetry((value) => value + 1)}>重试读取身份</button> : null };
}

const time = (value) => value ? new Intl.DateTimeFormat("zh-CN", {
  month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  hour12: false,
}).format(new Date(value)) : "-";

function MachineControlDialogBody({ action, targets, title, onClose, onComplete }) {
  const [reason, setReason] = useState("");
  const [ticket, setTicket] = useState(null);
  const request = useControlRequest(controlScope("machine", action, targets.map((target) => target.machine_id)), (value) => { setTicket(value); setReason(value.reason || ""); }, onClose, onComplete);
  const { busy, error } = request;
  const [pin, setPin] = useState("");
  const [typedMachine, setTypedMachine] = useState("");
  const [acceptanceReference, setAcceptanceReference] = useState("");
  const requiresReason = [
    "graceful_stop", "emergency_stop_network", "emergency_stop_host",
    "restart_supervisor", "force_restart_supervisor", "set_hard_capacity",
  ].includes(action) || (action === "set_admin_mode" && targets.some((target) => ["paused", "emergency_stop"].includes(target.requested_mode)));

  const preview = () => request.preview(async () => {
    setTicket(await api("/v1/admin/machine-controls/preview", {
      method: "POST", body: JSON.stringify({ action, targets: action === "accept_hard_capacity"
        ? targets.map((target) => ({ ...target, acceptance_reference: acceptanceReference })) : targets, reason }),
    }));
  });
  const confirm = async () => { const currentPin = pin; setPin(""); return request.confirm("/v1/admin/machine-controls/confirm", {
    ticket_id: ticket.ticket_id, confirmation_hash: ticket.confirmation_hash,
    break_glass_pin: ticket.requires_break_glass ? currentPin : null,
    typed_machine_id: ticket.requires_break_glass ? typedMachine : null,
    process_set_hash: ticket.requires_break_glass ? ticket.impact[ticket.targets[0].machine_id]?.external_comsol_process_set_hash : null,
  }, ticket); };

  return <div className="modal-layer" role="dialog" aria-modal="true" aria-label={title}>
    <button className="modal-backdrop" aria-label="关闭" disabled={busy || request.locked} onClick={onClose} />
    <section className="control-dialog">
      <header><div><span>PREVIEW / CONFIRM</span><h2>{title}</h2><p>{targets.map((target) => target.machine_id).join(" · ")}</p></div><button className="icon-button" title="关闭" disabled={busy || request.locked} onClick={onClose}><X size={18} /></button></header>
      {!ticket ? <div className="dialog-body">
        <div className="impact-note"><AlertTriangle size={17} /><span>确认时会重新核对策略、运行时、心跳、活动 attempt 和目标容量。任一目标发生变化，整批操作都会被拒绝。</span></div>
        {action === "set_target_capacity" && <div className="capacity-contract-note"><span>这里保存的是目标并发。压力、遥测、Profile 或资源门槛仍可将有效并发降到更低。</span></div>}
        {action === "set_hard_capacity" && <div className="capacity-contract-note"><span>这是管理员维护的硬上限。超过已验收部分会标记为“管理员强制 · 待 Agent 验收”，验收完成前不会用于派发；压力和 stale 保护仍可继续降容。</span></div>}
        {action === "accept_hard_capacity" && <div className="capacity-contract-note"><span>绑定 Agent 的容量验收记录后，清除“待验收”标记，不改变当前硬上限。</span></div>}
        {action === "accept_hard_capacity" && <label>验收记录标识 <b>必填</b><input disabled={busy} value={acceptanceReference} onChange={(event) => setAcceptanceReference(event.target.value)} placeholder="例如 campaign / test / run 编号" /></label>}
        <label>操作原因 {requiresReason ? <b>必填</b> : <small>可选</small>}<textarea disabled={busy} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="说明本次操作的上下文" /></label>
      </div> : <div className="dialog-body">
        <div className="ticket-summary"><span>票据 {ticket.ticket_id}</span><b>{ticket.action}</b><small>有效至 {time(ticket.expires_at)}</small></div>
        <div className="impact-grid">{ticket.targets.map((target) => {
          const impact = ticket.impact[target.machine_id] || {};
          return <article key={target.machine_id}><h3>{target.machine_id}</h3><dl><div><dt>所有者模式</dt><dd>{impact.owner_mode}</dd></div><div><dt>管理员覆盖</dt><dd>{impact.admin_override || "无"}</dd></div><div><dt>当前目标</dt><dd>{impact.current_target_capacity}</dd></div>{action === "set_target_capacity" && <div><dt>本次请求</dt><dd><b>{target.target_concurrent_units}</b></dd></div>}{action === "set_hard_capacity" && <div><dt>请求硬上限</dt><dd><b>{target.hard_capacity_units}</b></dd></div>}<div><dt>硬上限</dt><dd>{impact.validated_hard_cap}</dd></div><div><dt>待验收</dt><dd>{impact.hard_capacity_pending_acceptance ? "是" : "否"}</dd></div><div><dt>活动 attempt</dt><dd>{impact.active_attempt_count}</dd></div><div><dt>{ticket.requires_break_glass ? "外部 COMSOL" : "外部计算进程"}</dt><dd>{impact.external_process_count ?? impact.external_comsol_process_count}</dd></div></dl></article>;
        })}</div>
        {ticket.requires_break_glass && <div className="break-glass-form"><div><ShieldAlert size={18} /><span>主机级终止会结束该机全部非保护 COMSOL 进程树，只能单机执行。</span></div><label>完整机器 ID<input disabled={busy} value={typedMachine} onChange={(event) => setTypedMachine(event.target.value)} autoComplete="off" /></label><label>独立应急 PIN<input type="password" disabled={busy} value={pin} onChange={(event) => setPin(event.target.value)} autoComplete="new-password" /></label></div>}
      </div>}
      {error && <div className="form-error dialog-error" role="alert">{error}</div>}{request.recovery}
      <footer><button className="button" disabled={busy || request.locked} onClick={ticket ? () => setTicket(null) : onClose}>{ticket ? "返回修改" : "取消"}</button>{!ticket
        ? <button className="button button-primary" disabled={busy || !request.ready || (requiresReason && !reason.trim()) || (action === "accept_hard_capacity" && !acceptanceReference.trim())} onClick={preview}>生成预览</button>
        : <button className="button button-primary" disabled={busy || !request.ready || (ticket.requires_break_glass && (!pin || typedMachine !== ticket.targets[0].machine_id))} onClick={confirm}><CheckCircle2 size={16} />{action === "set_target_capacity" ? "确认保存目标" : action === "set_hard_capacity" ? "确认硬上限" : action === "accept_hard_capacity" ? "确认验收" : "确认执行"}</button>}</footer>
    </section>
  </div>;
}

function DispatcherControlDialogBody({ action, snapshot, onClose, onComplete }) {
  const [reason, setReason] = useState("");
  const [ticket, setTicket] = useState(null);
  const request = useControlRequest(controlScope("dispatcher", action), (value) => { setTicket(value); setReason(value.reason || ""); }, onClose, onComplete);
  const { busy, error } = request;
  const requiresReason = ["stop", "restart", "force_stop"].includes(action);
  const preview = () => request.preview(async () => {
    setTicket(await api("/v1/admin/dispatcher-controls/preview", { method: "POST", body: JSON.stringify({ action, reason }) }));
  });
  const confirm = () => request.confirm("/v1/admin/dispatcher-controls/confirm", { ticket_id: ticket.ticket_id, confirmation_hash: ticket.confirmation_hash }, ticket);
  return <div className="modal-layer" role="dialog" aria-modal="true" aria-label={`Dispatcher ${action}`}><button className="modal-backdrop" aria-label="关闭" disabled={busy || request.locked} onClick={onClose} /><section className="control-dialog compact-dialog"><header><div><span>DISPATCHER CONTROL</span><h2>{action}</h2><p>{snapshot?.phase || "unknown"} · lease {snapshot?.lease_owner || "none"}</p></div><button className="icon-button" title="关闭" disabled={busy || request.locked} onClick={onClose}><X size={18} /></button></header><div className="dialog-body">{!ticket ? <label>操作原因 {requiresReason ? <b>必填</b> : <small>可选</small>}<textarea disabled={busy} value={reason} onChange={(event) => setReason(event.target.value)} /></label> : <div className="ticket-summary"><span>{ticket.ticket_id}</span><b>{ticket.action}</b><small>有效至 {time(ticket.expires_at)}</small></div>}</div>{error && <div className="form-error dialog-error" role="alert">{error}</div>}{request.recovery}<footer><button className="button" disabled={busy || request.locked} onClick={ticket ? () => setTicket(null) : onClose}>返回</button><button className="button button-primary" disabled={busy || !request.ready || (!ticket && requiresReason && !reason.trim())} onClick={ticket ? confirm : preview}>{ticket ? "确认执行" : "生成预览"}</button></footer></section></div>;
}

function RuntimeControlDialogBody({ machineId, action, onClose, onComplete }) {
  const [reason, setReason] = useState("");
  const [ticket, setTicket] = useState(null);
  const request = useControlRequest(controlScope("runtime", action, [machineId]), (value) => { setTicket(value); setReason(value.reason || ""); }, onClose, onComplete);
  const { busy, error } = request;
  const preview = () => request.preview(async () => {
    setTicket(await api(`/v1/admin/machines/${machineId}/runtime-controls/preview`, { method: "POST", body: JSON.stringify({ action, reason }) }));
  });
  const confirm = () => request.confirm(`/v1/admin/machines/${machineId}/runtime-controls/confirm`, { ticket_id: ticket.ticket_id, confirmation_hash: ticket.confirmation_hash }, ticket);
  const impact = ticket?.impact?.[machineId] || {};
  return <div className="modal-layer" role="dialog" aria-modal="true" aria-label={`${machineId} runtime control`}>
    <button className="modal-backdrop" aria-label="关闭" disabled={busy || request.locked} onClick={onClose} />
    <section className="control-dialog compact-dialog"><header><div><span>SEALED RUNTIME CONTROL</span><h2>{action === "promote_runtime" ? "晋升候选运行时" : "回滚运行时"}</h2><p>{machineId}</p></div><button className="icon-button" title="关闭" disabled={busy || request.locked} onClick={onClose}><X size={18} /></button></header>
      <div className="dialog-body">{!ticket ? <><div className="impact-note"><AlertTriangle size={17} /><span>仅允许空闲、在线且已通过验收的节点。确认时会再次核对 supervisor 实例、启动任务、正式版本和远端密封产物。</span></div><label>操作原因 <b>必填</b><textarea disabled={busy} value={reason} onChange={(event) => setReason(event.target.value)} /></label></> : <><div className="ticket-summary"><span>{ticket.ticket_id}</span><b>{ticket.action}</b><small>有效至 {time(ticket.expires_at)}</small></div><dl className="runtime-ticket"><div><dt>当前运行</dt><dd>{impact.running_runtime_version || "-"}</dd></div><div><dt>正式版本</dt><dd>{impact.formal_runtime_version || "-"}</dd></div><div><dt>目标版本</dt><dd>{impact.target_runtime_version || "-"}</dd></div><div><dt>密封产物</dt><dd>{impact.target_runtime_available ? "已验证" : "不可用"}</dd></div></dl></>}</div>
      {error && <div className="form-error dialog-error" role="alert">{error}</div>}{request.recovery}<footer><button className="button" disabled={busy || request.locked} onClick={ticket ? () => setTicket(null) : onClose}>{ticket ? "返回修改" : "取消"}</button><button className="button button-primary" disabled={busy || !request.ready || (!ticket && !reason.trim())} onClick={ticket ? confirm : preview}>{ticket ? "确认执行" : "生成预览"}</button></footer>
    </section>
  </div>;
}

export function MachineControlDialog(props) { return <MachineControlDialogBody key={JSON.stringify(controlScope("machine", props.action, props.targets.map((target) => target.machine_id)))} {...props} />; }
export function DispatcherControlDialog(props) { return <DispatcherControlDialogBody key={props.action} {...props} />; }
export function RuntimeControlDialog(props) { return <RuntimeControlDialogBody key={`${props.machineId}:${props.action}`} {...props} />; }
