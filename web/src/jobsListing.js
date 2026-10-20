const CURRENT_STATUSES = ["awaiting_approval", "queued", "running", "failed_retriable"];

const newestJob = (previous, next) => {
  if (!previous) return next;
  const knownRevision = (value) => Number.isSafeInteger(value) && value >= 0;
  if (knownRevision(previous.revision) && knownRevision(next.revision) && previous.revision !== next.revision) {
    return previous.revision > next.revision ? previous : next;
  }
  const previousTime = Date.parse(previous.updated_at);
  const nextTime = Date.parse(next.updated_at);
  if (Number.isFinite(previousTime) && (!Number.isFinite(nextTime) || previousTime > nextTime)) return previous;
  // Equal (or both unknown) timestamps retain the later source's priority:
  // current lookups carry the unit details needed by the board and drawer.
  return next;
};

const mergeJobs = (...lists) => {
  const merged = new Map();
  for (const job of lists.flat()) merged.set(job.job_id, newestJob(merged.get(job.job_id), job));
  return [...merged.values()]
    .sort((a, b) => (b.created_at || "").localeCompare(a.created_at || "") || a.job_id.localeCompare(b.job_id));
};

export function applyJobsListing(previous, { jobs, received, loadState }) {
  const observedIds = new Set(jobs.map((job) => job.job_id));
  const merged = received ? mergeJobs(previous?.jobs || [], jobs) : [];
  return {
    ...(previous || {}),
    // Keep the previous list (and open drawer) while refresh pages arrive.
    // A settled read keeps only the observed range, while an older response
    // cannot replace a newer version already held by the app.
    ...(received ? { jobs: loadState.status === "loading" || loadState.error ? merged : merged.filter((job) => observedIds.has(job.job_id)) } : {}),
    jobsLoad: loadState,
    ...(received && loadState.status !== "loading" ? { jobsUpdatedAt: new Date().toISOString() } : {}),
  };
}

// Bound periodic history reads while looking up nonterminal work separately:
// a long-running Job must not disappear behind newer, finished submissions.
export async function loadJobsListing(request, { pageSize = 50, maxJobs = 50, currentMax = 5000, history = true, onProgress = () => {} } = {}) {
  const sources = [
    { statuses: [], jobs: new Map(), pages: 0, done: !history, complete: !history, error: "" },
    { statuses: CURRENT_STATUSES, jobs: new Map(), pages: 0, done: false, complete: false, error: "" },
  ];
  let fatalError = null;
  const snapshot = () => {
    const [listing, current] = sources;
    const received = sources.some((source) => source.pages > 0);
    const complete = sources.every((source) => source.complete);
    return {
      // Central revisions win before timestamps; current lookup breaks ties.
      jobs: mergeJobs([...listing.jobs.values()], [...current.jobs.values()]),
      received,
      loadState: {
        status: sources.some((source) => !source.done) ? "loading" : complete ? "complete" : received ? "partial" : "error",
        listComplete: listing.complete,
        currentComplete: current.complete,
        limit: maxJobs,
        hasMore: history && !listing.complete,
        historyCount: listing.jobs.size,
        error: sources.map((source, index) => source.error ? `${index ? "当前任务" : "运行记录"}：${source.error}` : "").filter(Boolean).join("；"),
      },
    };
  };
  const publish = () => onProgress(snapshot());
  publish();
  const read = async (source) => {
    if (source.done) return;
    let offset = 0;
    const sourceMax = source.statuses.length ? currentMax : maxJobs;
    try {
      while (offset < sourceMax && !fatalError) {
        const limit = Math.min(pageSize, sourceMax - offset);
        const params = new URLSearchParams({ limit: String(limit), offset: String(offset), view: "compact" });
        for (const status of source.statuses) params.append("status", status);
        const page = await request(`/v1/jobs?${params}`);
        if (!Array.isArray(page)) throw new Error("Job 列表响应格式错误");
        source.pages += 1;
        for (const job of page) source.jobs.set(job.job_id, newestJob(source.jobs.get(job.job_id), job));
        offset += page.length;
        if (page.length < limit) {
          source.complete = true;
          break;
        }
        // At this source's bound, finally publishes the settled page once.
        // Intermediate pages still reach the UI before the next request.
        if (offset < sourceMax) publish();
      }
    } catch (error) {
      if (error.status === 401) {
        fatalError = error;
        throw error;
      }
      source.error = error.message || "读取失败";
    } finally {
      source.done = true;
      publish();
    }
  };
  await Promise.allSettled([read(sources[1]), read(sources[0])]);
  if (fatalError) throw fatalError;
  return snapshot();
}

export function jobsLoadRangeText(state) {
  if (!state || state.status === "loading") return "正在分页加载运行记录";
  if (state.status === "complete") return "可见 Job 分页读取完成";
  if (state.status === "error") return "运行记录读取失败";
  const current = state.currentComplete ? "当前任务已单独读取" : "当前任务范围尚未确认";
  return `仅已加载的部分记录 · ${current}${state.error ? " · 部分读取失败" : ` · 已读取最近 ${state.historyCount ?? state.limit} 条，可加载更多`}`;
}
