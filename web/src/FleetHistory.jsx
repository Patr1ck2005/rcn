import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import { api } from "./api";
import { usePageRefresh } from "./usePageRefresh";

export function FleetGroupSummary() {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  usePageRefresh(() => setRevision((value) => value + 1), { resources: ["machines"] });
  useEffect(() => {
    const controller = new AbortController();
    api("/v1/operations/summary", { signal: controller.signal }).then((next) => { setSummary(next); setError(""); }).catch((caught) => {
      if (!controller.signal.aborted) setError(caught.message);
    });
    return () => controller.abort();
  }, [revision]);
  return <p className="fleet-scope-note fleet-group-summary">群组运行概况：{summary
    ? <>健康 {summary.machines?.healthy ?? 0} 台 · 当前 Job {summary.jobs?.current ?? 0} · 调度器 {summary.dispatcher?.phase || "未知"}<small> · 快照 {new Date(summary.generated_at).toLocaleTimeString("zh-CN", { hour12: false })}，不包含其他成员详情</small></>
    : error || "正在读取汇总…"}</p>;
}

export default function FleetHistory({ records, matches, query }) {
  if (!records.length) return null;
  return <details className="data-section fleet-history">
    <summary>历史记录（{records.length}）{query && <small> · 匹配 {matches.length} 条</small>}</summary>
    <p>已撤销的注册身份，仅供追溯。不计入现役在线率、容量或普通离线告警。</p>
    <div className="fleet-history-list">{matches.map((machine) => <article key={machine.machine_id}>
      <div><b>{machine.display_name || machine.machine_id}</b><small>{machine.machine_id} · {machine.owner_user_id}</small></div>
      <span className="fleet-history-label">已撤销 · 历史</span>
      <Link className="button small" to={`/app/machines/${machine.machine_id}`}>查看详情</Link>
      <Link className="button small" to={`/app/machines/${machine.machine_id}?tab=events`}>查看审计</Link>
    </article>)}</div>
    {!matches.length && <p>没有匹配的历史记录。</p>}
  </details>;
}
