import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { JobDrawer, JobProgress } from "./App";
import { estimateEta, formatEta, unitEtaLabel } from "./format";
import { currentJobPhase, jobEnvironmentLabel, jobEta, jobPhaseLabel, jobStatusPresentation, reconciliationState } from "./jobActivity";

const lostUnit = (ordinal = 0) => ({
  work_unit_id: `lost-${ordinal}`, ordinal, status: "reconcile_pending",
  activity_state: "finalizing", dispatch_phase: "running", assigned_machine_id: "demo-node-a",
  total_items: 4, completed_items: 0, eta_s: 209.844, eta_confidence: "worker",
  attempts: [{ state: "uncertain", machine_id: "demo-node-a", started_at: "2026-10-04T10:00:00Z", finished_at: null }],
});
const screenshotJob = () => ({
  job_id: "job-synthetic-progress", project_id: "demo-parameter-scan", user_id: "demo-researcher",
  status: "running", activity_phase: "finalizing", priority: 100,
  unit_count: 1056, completed_unit_count: 1050, completed_items: 4200, total_items: 4222,
  execution_started_at: "2026-10-04T10:00:00Z", total_elapsed_seconds: 694800,
  eta_seconds: 209.844, eta_lower_seconds: 209.844, eta_upper_seconds: 64800,
  eta_confidence: "worker", eta_at: "2026-10-12T23:14:03Z",
  execution_environment: { status: "executable", capacity_hint: { eligible_slots: 9 } },
  work_units: [
    ...Array.from({ length: 1050 }, (_, ordinal) => ({ work_unit_id: `done-${ordinal}`, ordinal, status: "completed", total_items: 4 })),
    ...Array.from({ length: 6 }, (_, ordinal) => lostUnit(ordinal + 1050)),
  ],
});

describe("reconciliation presentation", () => {
  it("labels explicitly omitted historical environment checks without inventing current readiness", () => {
    const historical = { status: "completed", activity_state: "history", execution_environment: null, execution_environment_state: "not_requested", project_concurrency: null, project_concurrency_state: "not_requested", work_units: [{ status: "completed", attempts: [{ state: "completed", finished_at: "2026-10-17T12:00:00Z" }] }] };
    expect(jobEnvironmentLabel(historical)).toBe("历史执行已结束；当前环境按需检查");
    expect(jobStatusPresentation(historical)).toEqual({ value: "completed" });
    expect(jobEnvironmentLabel({ status: "completed", execution_environment: null })).toBe("环境状态未知");
    const html = renderToStaticMarkup(<MemoryRouter><JobDrawer job={{ ...historical,
      job_id: "history", project_id: "project", user_id: "alice", created_at: "2026-10-17T12:00:00Z",
      updated_at: "2026-10-17T12:00:00Z" }} machines={[]} admin={false} /></MemoryRouter>);
    expect(html).toContain("历史记录按需检查");
  });

  it("does not classify terminal Jobs with live or reconciling Attempts as finished history", () => {
    const terminal = { status: "cancelled", execution_environment_state: "not_requested", execution_environment: null, work_units: [{ status: "cancelled", attempts: [{ state: "running", finished_at: null }] }] };
    expect(jobEnvironmentLabel(terminal)).toBe("环境状态未知");
    expect(jobEnvironmentLabel({ ...terminal, execution_environment_state: "ready", execution_environment: { status: "executable", capacity_hint: { eligible_slots: 2 } } })).toBe("环境就绪 · 2 可用 slot");
    expect(jobEnvironmentLabel({ ...terminal, reconciliation_unit_count: 1, reconciliation_machine_ids: ["demo-node-a"] })).toBe("等待 demo-node-a 对账 · 没有待派发单元");
  });

  it("keeps queued work current even when an omitted-check marker is inconsistent", () => {
    expect(jobEnvironmentLabel({ status: "queued", queued_unit_count: 1, execution_environment_state: "not_requested", execution_environment: { status: "blocked_by_approval" } })).toBe("等待当前 Runtime 审批");
  });
  it("renders the screenshot as waiting for the identified machine instead of a stale countdown", () => {
    const job = screenshotJob();
    const before = JSON.stringify(job);
    const html = renderToStaticMarkup(<JobProgress job={job} />);
    expect(html).toContain("等待 demo-node-a 对账");
    expect(html).toContain("等待对账 6");
    expect(html).toContain("完成 1050");
    expect(html).toContain("6 个单元执行状态未知");
    expect(html).toContain("暂无可靠估计");
    expect(html).not.toContain("9 可用 slot");
    expect(html).not.toContain("运行中");
    expect(html).not.toContain("导出终结中");
    expect(html).not.toContain("<span>预计完成 <b>");
    expect(html).not.toContain("worker");
    expect(JSON.stringify(job)).toBe(before);
  });

  it("keeps the drawer and its unit ETA consistent with the queue card", () => {
    const job = { ...screenshotJob(), work_units: [lostUnit()] };
    const html = renderToStaticMarkup(<MemoryRouter><JobDrawer job={job} machines={[]} admin={false} /></MemoryRouter>);
    expect(html).toContain("等待 demo-node-a 对账");
    expect(html).toContain("等待对账 · 暂无可靠估计");
    expect(html).not.toContain("3 分 30 秒");
    expect(html).not.toContain("23:14:03");
    expect(html).not.toContain("导出终结中");
  });

  it("uses explicit compact summary evidence without inventing a machine identity", () => {
    const compact = { ...screenshotJob(), work_units: [], activity_phase: "reconcile_pending", reconciliation_unit_count: 6 };
    expect(jobStatusPresentation(compact)).toEqual({ value: "reconcile_pending", text: "等待对账" });
    expect(jobEnvironmentLabel(compact)).toBe("等待对账 · 没有待派发单元");
    expect(jobEta(compact)).toMatchObject({ seconds: null, at: null });
    expect(jobPhaseLabel({ ...compact, reconciliation_machine_ids: ["demo-node-a", "demo-node-a"] })).toBe("等待 demo-node-a 对账");
  });

  it("withdraws the overall ETA for mixed known and unknown execution while showing real active units", () => {
    const job = {
      ...screenshotJob(), work_units: [lostUnit(), { status: "running", total_items: 4 }, { status: "queued", total_items: 4 }],
    };
    const html = renderToStaticMarkup(<JobProgress job={job} />);
    expect(html).toContain("运行中 1");
    expect(html).toContain("排队 1");
    expect(html).toContain("等待对账 1");
    expect(html).toContain("9 可用 slot");
    expect(jobEta(job)).toMatchObject({ seconds: null, at: null });
  });

  it("keeps valid running, finalizing and collecting estimates and phases", () => {
    for (const phase of ["running", "finalizing", "collecting"]) {
      const job = {
        ...screenshotJob(), activity_phase: phase,
        work_units: [{ status: phase === "finalizing" ? "running" : phase, dispatch_phase: phase }],
        eta_seconds: 90, eta_lower_seconds: null, eta_upper_seconds: null, eta_confidence: "high",
      };
      expect(currentJobPhase(job)).toBe(phase);
      expect(reconciliationState(job).pending).toBe(false);
      expect(jobEta(job)).toMatchObject({ seconds: 90, label: "1 分 30 秒 · high", at: job.eta_at });
      expect(jobStatusPresentation(job)).toEqual({ value: "running" });
    }
  });

  it("honors a withdrawn server ETA instead of reconstructing it from cumulative throughput", () => {
    const base = {
      completed_items: 100, total_items: 101, execution_started_at: "2026-10-01T10:00:00Z",
      eta_seconds: null, eta_at: "2026-10-12T23:14:03Z", work_units: [{ status: "running" }],
    };
    for (const evidence of [{ eta_confidence: "unknown" }, { eta_blocked_reason: "stale_worker_observation" }]) {
      expect(jobEta({ ...base, ...evidence })).toMatchObject({ seconds: null, at: null, label: "暂无可靠估计" });
    }
    expect(jobEta(base).seconds).toBeGreaterThan(0);
    expect(estimateEta({ completed: 100, total: 101, startedAt: base.execution_started_at, allowFallback: false }).seconds).toBe(null);
    expect(formatEta(null)).toBe("暂无可靠估计");
  });

  it("ignores a historical uncertain attempt once its unit is completed", () => {
    const unit = { ...lostUnit(), status: "completed", activity_state: "completed" };
    const job = { status: "completed", work_units: [unit], completed_items: 4, total_items: 4 };
    expect(reconciliationState(job).pending).toBe(false);
    expect(currentJobPhase(job)).toBe("completed");
    expect(unitEtaLabel(lostUnit(), 600)).toBe("等待对账 · 暂无可靠估计");
  });
});
