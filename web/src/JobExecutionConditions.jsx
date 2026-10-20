import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { api } from "./api";
import { DataLoadState, RefreshStatus } from "./AsyncState";
import { jobEnvironmentLabel } from "./jobActivity";
import { usePageRefresh } from "./usePageRefresh";

const amount = (value) => value != null && value !== "" && typeof value !== "boolean" && Number.isFinite(Number(value))
  ? Number(value).toLocaleString("zh-CN") : "未知";
const time = (value) => Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "检查时间未知";

export function JobExecutionConditionsSnapshot({ data }) {
  const concurrency = data.project_concurrency;
  return <div className="execution-conditions-result">
    <p>{jobEnvironmentLabel({ execution_environment: data.execution_environment })}</p>
    <p>当前项目：{amount(concurrency?.active_units)} 运行 + {amount(concurrency?.prepared_units)} 预备 / {amount(concurrency?.max_running_units)} 上限</p>
    <p>检查时间 <time dateTime={data.generated_at}>{time(data.generated_at)}</time></p>
  </div>;
}

export default function JobExecutionConditions({ actorId, jobId }) {
  const scope = `${actorId}:${jobId}`;
  const [state, setState] = useState({ scope, data: null, error: "", loading: false });
  const load = usePageRefresh(async ({ signal, isCurrent }) => {
    setState((current) => current.scope === scope ? { ...current, error: "", loading: true } : { scope, data: null, error: "", loading: true });
    try {
      const data = await api(`/v1/jobs/${encodeURIComponent(jobId)}/execution-conditions`, { signal });
      if (data?.job_id !== jobId) throw new Error("当前执行条件响应与原 Job 不匹配。");
      if (isCurrent()) setState({ scope, data, error: "", loading: false });
    } catch (caught) {
      if (isCurrent()) setState((current) => ({ ...current, error: caught.message, loading: false }));
    }
  }, { key: scope, initial: false, listen: false, intervalMs: 0, enabled: Boolean(actorId && jobId) });
  const { data, error, loading } = state.scope === scope ? state : { data: null, error: "", loading: false };
  const check = () => load({ reason: "manual", join: true });
  return <section className="drawer-control" aria-label="当前执行条件检查">
    <h3>当前执行条件</h3><p>按需检查当前环境和项目并发，不改变历史执行结果。</p>
    <button className="button" disabled={!actorId || loading} onClick={check}><RefreshCw size={15} className={loading ? "spin" : ""} />检查当前执行条件</button>
    <RefreshStatus visible={loading && Boolean(data)} label="正在检查当前执行条件" />
    {!data && (loading || error) && <DataLoadState compact label="正在检查当前执行条件" error={error} onRetry={check} />}
    {data && <JobExecutionConditionsSnapshot data={data} />}
    {data && error && <p className="form-error" role="alert">检查失败：{error}。保留 {time(data.generated_at)} 的上次结果。</p>}
  </section>;
}
