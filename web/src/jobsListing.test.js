import { describe, expect, it, vi } from "vitest";
import { applyJobsListing, jobsLoadRangeText, loadJobsListing } from "./jobsListing";
import { createReadScheduler } from "./readScheduler";

const loadAllJobs = (request, options = {}) => loadJobsListing(request, { maxJobs: 5000, ...options });

const job = (id, status = "completed", project = "recent-project") => ({
  job_id: `job-${id}`, status, project_id: project,
  activity_state: status === "running" ? "active" : status === "queued" ? "queued" : "history",
  created_at: new Date(Date.UTC(2026, 9, 1) - id * 1000).toISOString(),
  updated_at: "2026-10-01T09:00:00Z",
  work_units: [{ work_unit_id: `unit-${id}`, status }],
});
const endpoint = (records) => vi.fn(async (path) => {
  const params = new URL(path, "http://test").searchParams;
  const statuses = params.getAll("status");
  const visible = statuses.length ? records.filter((record) => statuses.includes(record.status)) : records;
  return visible.slice(Number(params.get("offset")), Number(params.get("offset")) + Number(params.get("limit")));
});

describe("Runs visible Job listing", () => {
  it("finds an older running Job and project beyond the former newest-200 window", async () => {
    const records = [...Array.from({ length: 1200 }, (_, index) => job(index)), job(1200, "running", "older-project"), job(1201, "completed", "older-project")];
    const request = endpoint(records);
    const result = await loadAllJobs(request);
    expect(result.jobs).toHaveLength(1202);
    expect(result.jobs.filter((record) => record.activity_state === "active").map((record) => record.job_id)).toEqual(["job-1200"]);
    expect(result.jobs.filter((record) => record.project_id === "older-project").map((record) => record.job_id)).toEqual(["job-1200", "job-1201"]);
    expect(result.jobs.find((record) => record.job_id === "job-1200").work_units[0].work_unit_id).toBe("unit-1200");
    expect(result.loadState.status).toBe("complete");
    expect(jobsLoadRangeText(result.loadState)).toBe("可见 Job 分页读取完成");
    expect(request.mock.calls.every(([path]) => new URL(path, "http://test").searchParams.get("view") === "compact")).toBe(true);
  });

  it("keeps older current work visible when the bounded history read is truncated", async () => {
    const records = [...Array.from({ length: 600 }, (_, index) => job(index)),
      ...["awaiting_approval", "queued", "running", "failed_retriable"].map((status, index) => job(600 + index, status, "older-project"))];
    const result = await loadAllJobs(endpoint(records), { maxJobs: 500 });
    expect(result.jobs).toHaveLength(504);
    expect(result.jobs.filter((record) => record.project_id === "older-project")).toHaveLength(4);
    expect(result.loadState).toMatchObject({ status: "partial", listComplete: false, currentComplete: true });
    expect(jobsLoadRangeText(result.loadState)).toContain("部分记录");
    expect(jobsLoadRangeText(result.loadState)).not.toContain("读取完成");
  });

  it("retains successful pages and older current work after a later history page fails", async () => {
    const records = [...Array.from({ length: 700 }, (_, index) => job(index)), job(700, "running", "older-project")];
    const normal = endpoint(records);
    const result = await loadAllJobs(async (path) => {
      const params = new URL(path, "http://test").searchParams;
      if (!params.has("status") && Number(params.get("offset")) >= 500) throw new Error("second page unavailable");
      return normal(path);
    });
    expect(result.jobs).toHaveLength(501);
    expect(result.jobs.find((record) => record.job_id === "job-700").status).toBe("running");
    expect(result.loadState).toMatchObject({ status: "partial", currentComplete: true });
    expect(result.loadState.error).toContain("second page unavailable");
    expect(jobsLoadRangeText(result.loadState)).toContain("部分读取失败");
  });

  it("publishes current work while history is still loading and deduplicates the later page", async () => {
    const records = [{ ...job(0, "running"), updated_at: "2026-10-01T09:01:00Z" }];
    let releaseHistory;
    const history = new Promise((resolve) => { releaseHistory = resolve; });
    const progress = [];
    const operation = loadAllJobs((path) => new URL(path, "http://test").searchParams.has("status") ? Promise.resolve(records) : history, { onProgress: (snapshot) => progress.push(snapshot) });
    await Promise.resolve();
    await Promise.resolve();
    expect(progress.at(-1).jobs.map((record) => record.job_id)).toEqual(["job-0"]);
    expect(progress.at(-1).loadState.status).toBe("loading");
    expect(jobsLoadRangeText(progress.at(-1).loadState)).not.toContain("读取完成");
    releaseHistory([{ ...records[0], status: "queued", activity_state: "queued", updated_at: "2026-10-01T09:00:00Z", work_units: [] }]);
    const result = await operation;
    expect(result.jobs).toHaveLength(1);
    expect(result.jobs[0].status).toBe("running");
    expect(result.loadState.status).toBe("complete");
  });

  it.each(["completed", "cancelled"])("does not revive a Job when current lookup precedes a newer %s transition", async (terminalStatus) => {
    const running = job(0, "running");
    const finished = { ...job(0, terminalStatus), updated_at: "2026-10-01T09:01:00Z" };
    let releaseHistory;
    const history = new Promise((resolve) => { releaseHistory = resolve; });
    let data = null;
    const operation = loadAllJobs((path) => new URL(path, "http://test").searchParams.has("status") ? Promise.resolve([running]) : history, {
      onProgress: (snapshot) => { data = applyJobsListing(data, snapshot); },
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(data.jobs[0].status).toBe("running");
    releaseHistory([finished]);
    const result = await operation;
    expect(result.jobs).toEqual([finished]);
    expect(data.jobs).toEqual([finished]);
    expect(data.jobs.filter((record) => ["active", "queued"].includes(record.activity_state))).toEqual([]);
  });

  it("keeps richer current unit details when history and current timestamps agree", async () => {
    const current = job(0, "running");
    const summary = { ...current, work_units: [] };
    const result = await loadAllJobs(async (path) => new URL(path, "http://test").searchParams.has("status") ? [current] : [summary]);
    expect(result.jobs).toEqual([current]);
  });

  it("prefers a newer central revision despite clock rollback on its terminal transition", async () => {
    const current = { ...job(0, "running"), revision: 4, updated_at: "2026-10-01T09:02:00Z" };
    const terminal = { ...job(0, "completed"), revision: 5, updated_at: "2026-10-01T09:01:00Z" };
    const result = await loadAllJobs(async (path) => new URL(path, "http://test").searchParams.has("status") ? [current] : [terminal]);
    expect(result.jobs).toEqual([terminal]);
    const cached = applyJobsListing({ jobs: [terminal] }, { jobs: [current], received: true, loadState: { status: "complete" } });
    expect(cached.jobs).toEqual([terminal]);
  });

  it("uses the newer timestamp when central revisions are equal", async () => {
    const current = { ...job(0, "running"), revision: 4 };
    const terminal = { ...job(0, "cancelled"), revision: 4, updated_at: "2026-10-01T09:01:00Z" };
    const result = await loadAllJobs(async (path) => new URL(path, "http://test").searchParams.has("status") ? [current] : [terminal]);
    expect(result.jobs).toEqual([terminal]);
  });

  it.each(["current", "history"])("uses timestamps without treating a missing %s revision as zero", async (missingRevisionSource) => {
    const current = { ...job(0, "running"), ...(missingRevisionSource === "current" ? {} : { revision: 7 }) };
    const terminal = { ...job(0, "completed"), updated_at: "2026-10-01T09:01:00Z", ...(missingRevisionSource === "history" ? {} : { revision: 6 }) };
    const result = await loadAllJobs(async (path) => new URL(path, "http://test").searchParams.has("status") ? [current] : [terminal]);
    expect(result.jobs).toEqual([terminal]);
  });

  it.each(["loading", "complete"])("keeps a newer cached terminal transition when an older refresh response is %s", (status) => {
    const finished = { ...job(0, "completed"), updated_at: "2026-10-01T09:02:00Z" };
    const oldRunning = { ...job(0, "running"), updated_at: "2026-10-01T09:01:00Z" };
    const data = applyJobsListing({ jobs: [finished] }, { jobs: [oldRunning], received: true, loadState: { status } });
    expect(data.jobs).toEqual([finished]);
  });

  it("removes records outside the new settled visible range while retaining newer versions within it", () => {
    const finished = { ...job(0), updated_at: "2026-10-01T09:02:00Z" };
    const data = applyJobsListing({ jobs: [finished, job(1)] }, { jobs: [job(0, "running")], received: true, loadState: { status: "complete" } });
    expect(data.jobs).toEqual([finished]);
  });

  it("keeps a loaded drawer record throughout refresh and preserves cached content on total failure", async () => {
    const selected = job(800, "completed", "older-project");
    let data = { jobs: [selected], overview: { machines: [] } };
    const history = endpoint([job(0), selected]);
    const observed = [];
    await loadAllJobs(history, { pageSize: 1, onProgress: (snapshot) => {
      data = applyJobsListing(data, snapshot);
      observed.push(data);
    } });
    expect(observed.every((snapshot) => snapshot.jobs.some((record) => record.job_id === selected.job_id))).toBe(true);
    expect(data.overview).toEqual({ machines: [] });
    await loadAllJobs(async () => { throw new Error("offline"); }, { onProgress: (snapshot) => { data = applyJobsListing(data, snapshot); } });
    expect(data.jobs.find((record) => record.job_id === selected.job_id)).toEqual(selected);
    expect(data.jobsLoad.status).toBe("error");
  });

  it("marks an unconfirmed current range and a total failure explicitly", async () => {
    const currentFailure = await loadAllJobs(async (path) => {
      if (new URL(path, "http://test").searchParams.has("status")) throw new Error("current lookup failed");
      return [];
    });
    expect(currentFailure.loadState.status).toBe("partial");
    expect(jobsLoadRangeText(currentFailure.loadState)).toContain("当前任务范围尚未确认");
    const failure = await loadAllJobs(async () => { throw new Error("offline"); });
    expect(failure.received).toBe(false);
    expect(failure.loadState.status).toBe("error");
    expect(jobsLoadRangeText(failure.loadState)).toBe("运行记录读取失败");
  });

  it("preserves authentication failure for the app's existing login redirect", async () => {
    const error = Object.assign(new Error("expired token"), { status: 401 });
    await expect(loadAllJobs(async () => { throw error; })).rejects.toBe(error);
  });
});


describe("bounded initial Runs history", () => {
  it("starts current work before a held history request in a single-slot read queue", async () => {
    const scheduler = createReadScheduler({ limit: 1 });
    const current = job(900, "running", "older-project");
    let releaseHistory;
    const history = new Promise((resolve) => { releaseHistory = resolve; });
    const started = [], progress = [];
    const operation = loadJobsListing((path) => scheduler.run(() => {
      const isCurrent = new URL(path, "http://test").searchParams.has("status");
      started.push(isCurrent ? "current" : "history");
      return isCurrent ? [current] : history;
    }), { onProgress: (snapshot) => progress.push(snapshot) });
    for (let index = 0; index < 12; index += 1) await Promise.resolve();
    expect(started).toEqual(["current", "history"]);
    expect(progress.at(-1)).toMatchObject({ jobs: [current], loadState: { status: "loading", currentComplete: true } });
    releaseHistory([job(0)]);
    const result = await operation;
    expect(result.jobs.map((record) => record.job_id)).toEqual(["job-0", "job-900"]);
    expect(result.loadState).toMatchObject({ status: "complete", currentComplete: true, listComplete: true });
  });

  it("publishes an exact history bound once while keeping earlier current work visible", async () => {
    const historyRows = Array.from({ length: 50 }, (_, index) => job(index));
    const current = job(900, "running", "older-project");
    let releaseHistory;
    const history = new Promise((resolve) => { releaseHistory = resolve; });
    const progress = [];
    const operation = loadJobsListing((path) => new URL(path, "http://test").searchParams.has("status")
      ? Promise.resolve([current]) : history, { onProgress: (snapshot) => progress.push(snapshot) });
    await Promise.resolve();
    await Promise.resolve();
    expect(progress.at(-1)).toMatchObject({ jobs: [current], loadState: { status: "loading", currentComplete: true } });
    releaseHistory(historyRows);
    const result = await operation;
    const fullHistory = progress.filter((snapshot) => snapshot.loadState.historyCount === 50);
    expect(fullHistory).toHaveLength(1);
    expect(fullHistory[0]).toEqual(result);
    expect(result.jobs).toHaveLength(51);
    expect(result.loadState).toMatchObject({ status: "partial", hasMore: true, currentComplete: true });
  });

  it("still publishes intermediate pages before later requests settle and keeps them on failure", async () => {
    const records = Array.from({ length: 125 }, (_, index) => job(index));
    let releaseSecond;
    const second = new Promise((resolve) => { releaseSecond = resolve; });
    const progress = [];
    const operation = loadJobsListing(async (path) => {
      const params = new URL(path, "http://test").searchParams;
      if (params.has("status")) return [];
      const offset = Number(params.get("offset"));
      if (offset === 0) return records.slice(0, 50);
      if (offset === 50) return second;
      throw new Error("third history page unavailable");
    }, { maxJobs: 150, onProgress: (snapshot) => progress.push(snapshot) });
    await Promise.resolve();
    await Promise.resolve();
    expect(progress.some((snapshot) => snapshot.loadState.historyCount === 50 && snapshot.loadState.status === "loading")).toBe(true);
    releaseSecond(records.slice(50, 100));
    const result = await operation;
    expect(progress.some((snapshot) => snapshot.loadState.historyCount === 100 && snapshot.loadState.status === "loading")).toBe(true);
    expect(result.jobs).toHaveLength(100);
    expect(result.loadState).toMatchObject({ status: "partial", currentComplete: true, hasMore: true });
    expect(result.loadState.error).toContain("third history page unavailable");
  });

  it("loads only 50 history entries while finding all older current jobs", async () => {
    const records = [...Array.from({ length: 700 }, (_, index) => job(index)),
      ...Array.from({ length: 61 }, (_, index) => job(700 + index, "running", "older-project"))];
    const request = endpoint(records);
    const result = await loadJobsListing(request);
    expect(result.jobs).toHaveLength(111);
    expect(result.loadState).toMatchObject({ hasMore: true, historyCount: 50, currentComplete: true });
    const paths = request.mock.calls.map(([path]) => new URL(path, "http://test").searchParams);
    expect(paths.filter((params) => !params.has("status"))).toHaveLength(1);
    expect(paths.every((params) => Number(params.get("limit")) <= 50)).toBe(true);
  });
  it("does not read historical jobs for a current-only map", async () => {
    const request = endpoint([job(0), job(1, "running")]);
    const result = await loadJobsListing(request, { history: false });
    expect(result.jobs.map((item) => item.job_id)).toEqual(["job-1"]);
    expect(request.mock.calls.every(([path]) => new URL(path, "http://test").searchParams.has("status"))).toBe(true);
  });
  it("retains cached current jobs when only the current lookup fails", async () => {
    const previous = { jobs: [job(900, "running")] };
    const snapshot = await loadJobsListing(async (path) => {
      if (new URL(path, "http://test").searchParams.has("status")) throw new Error("offline current lookup");
      return [job(0)];
    });
    expect(applyJobsListing(previous, snapshot).jobs.map((item) => item.job_id)).toContain("job-900");
  });
});
