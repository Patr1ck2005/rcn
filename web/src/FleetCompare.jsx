import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, Cpu, MemoryStick, Server } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { api } from "./api";
import { usePageRefresh } from "./usePageRefresh";
import { DataLoadState } from "./AsyncState";

function ComparisonChart({ title, data, bars }) {
  return <section className="chart-panel comparison-chart"><header><h3>{title}</h3><span>当前真实 snapshot</span></header><div className="chart-body"><ResponsiveContainer width="100%" height="100%"><BarChart data={data} layout="vertical" margin={{ left: 12, right: 18 }}><CartesianGrid stroke="var(--line)" horizontal={false} /><XAxis type="number" domain={[0, 100]} unit="%" /><YAxis type="category" dataKey="machine" width={62} /><Tooltip /><Legend />{bars.map(([key, color, name]) => <Bar key={key} dataKey={key} fill={color} name={name} radius={[0, 2, 2, 0]} />)}</BarChart></ResponsiveContainer></div></section>;
}

export default function FleetCompare() {
  const [params] = useSearchParams();
  const ids = useMemo(() => (params.get("machines") || "").split(",").filter(Boolean).slice(0, 5), [params]);
  const [machines, setMachines] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(ids.length >= 2);
  const load = (background = false) => { if (!background) setLoading(true); setError(""); return api("/v1/machines").then((items) => setMachines(items.filter((item) => ids.includes(item.machine_id)))).catch((caught) => setError(caught.message)).finally(() => setLoading(false)); };
  usePageRefresh(() => ids.length >= 2 ? load(true) : undefined, { resources: ["machines", "jobs"] });
  useEffect(() => { if (ids.length >= 2) load(); else setLoading(false); }, [ids.join(",")]);
  const percentages = machines.map((machine) => ({
    machine: machine.machine_id,
    cpu: machine.metrics?.cpu_total_percent ?? null,
    memory: machine.metrics?.total_memory_mb ? machine.metrics.memory_used_mb / machine.metrics.total_memory_mb * 100 : null,
    gpu: machine.total_gpus ? machine.metrics?.gpu?.[0]?.utilization_percent ?? null : null,
    gpuMemory: machine.metrics?.gpu?.[0]?.memory_total_mb ? machine.metrics.gpu[0].memory_used_mb / machine.metrics.gpu[0].memory_total_mb * 100 : null,
    disk: machine.metrics?.total_disk_mb ? machine.metrics.disk_used_mb / machine.metrics.total_disk_mb * 100 : null,
  }));
  return <main className="app-page"><div className="detail-title"><Link className="icon-button" title="返回 Fleet" to={`/app/fleet?selected=${ids.join(",")}`}><ArrowLeft size={18} /></Link><div><span>FLEET / COMPARE</span><h1>多机对比</h1><p>{ids.join(" · ") || "未选择机器"}</p></div></div>{ids.length < 2
    ? <section className="detail-section"><p>请在 Fleet 勾选 2–5 台机器后进入对比。</p></section>
    : loading || error ? <DataLoadState label="正在加载机器对比" error={error} onRetry={load} /> : <><div className="compare-summary">{machines.map((machine) => <article key={machine.machine_id}><Server size={17} /><div><b>{machine.display_name || machine.machine_id}</b><small>{machine.operational_status?.supervisor_state} · {machine.operational_status?.telemetry_state}</small></div><strong>{machine.operational_status?.effective_capacity ?? machine.operational_status?.effective_comsol_concurrency ?? 0}</strong></article>)}</div><div className="chart-grid"><ComparisonChart title="CPU" data={percentages} bars={[["cpu", "#15936d", "CPU"]]} /><ComparisonChart title="内存" data={percentages} bars={[["memory", "#3184a1", "内存"]]} /><ComparisonChart title="GPU 与显存" data={percentages} bars={[["gpu", "#8b6ab4", "GPU"], ["gpuMemory", "#c88934", "显存"]]} /><ComparisonChart title="磁盘" data={percentages} bars={[["disk", "#697a71", "磁盘"]]} /></div></>}
  </main>;
}
