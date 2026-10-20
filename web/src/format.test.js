import { describe, expect, it } from "vitest";
import { attemptSegments, capacityDisplay, estimateEta, formatAge, formatDuration, formatIdle, formatMb, formatNumber, formatPercent, gpuDisplay, jobCompletionSeries, jobMachineDurations, jobProgressTotals, jobTimeWindow, statusLabel, unitEtaLabel, unitItemCount, unitReassignable } from "./format";

describe("format helpers", () => {
  it("formats telemetry age without hiding missing data", () => {
    const now = Date.parse("2026-08-18T12:00:30Z");
    expect(formatAge("2026-08-18T12:00:00Z", now)).toBe("30 秒前");
    expect(formatAge("2026-08-18T11:10:00Z", now)).toBe("50 分钟前");
    expect(formatAge(null, now)).toBe("暂无数据");
  });

  it("formats monitoring values", () => {
    expect(formatMb(2048)).toBe("2.0 GB");
    expect(formatIdle(1800)).toBe("30m");
    expect(statusLabel("emergency_stop")).toBe("紧急停止");
    expect(statusLabel("online")).toBe("执行器在线");
    expect(statusLabel("live")).toBe("遥测实时");
    expect(formatNumber(56.666666666664)).toBe("56.7");
    expect(formatPercent(100)).toBe("100%");
    expect(formatDuration(3661)).toBe("1 小时 1 分");
    expect(statusLabel("stale")).toBe("数据过期");
    expect(statusLabel("prepared")).toBe("已预备");
    expect(statusLabel("finalizing")).toBe("导出终结中");
    expect(statusLabel("transport_disconnected")).toBe("传输断开");
  });

  it("does not invent ETA without observed throughput", () => {
    expect(estimateEta({ completed: 0, total: 10 }).label).toBe("暂无可靠估计");
    expect(estimateEta({ etaSeconds: 90, confidence: "高" }).label).toBe("1 分 30 秒 · 高");
    expect(estimateEta({
      etaSeconds: 600,
      etaLowerSeconds: 480,
      etaUpperSeconds: 720,
      confidence: "medium",
    }).label).toBe("8 分 0 秒–12 分 0 秒 · medium");
  });

  it("keeps compact zero-sentinel counts from shadowing worker totals", () => {
    expect(unitItemCount({ atomic_item_count: 0, total_items: 7 })).toBe(7);
    expect(unitItemCount({ atomic_item_count: 3, total_items: null })).toBe(3);
    expect(unitItemCount({ atomic_item_ids: ["a", "b"] })).toBe(2);
    expect(unitItemCount({})).toBe(0);
    expect(unitItemCount(null)).toBe(0);
  });

  it("derives job progress totals from the decorated operational summary", () => {
    const job = {
      completed_items: 12,
      total_items: 5151,
      work_units: [
        { status: "running", atomic_item_count: 0, total_items: 7, completed_items: 3 },
        { status: "queued", atomic_item_count: 0, total_items: null, completed_items: null },
      ],
    };
    expect(jobProgressTotals(job)).toEqual({ completed: 12, total: 5151 });
    expect(jobProgressTotals({
      atomic_item_count: 202,
      work_units: [{ status: "completed", atomic_item_count: 1, completed_items: 1 }],
    })).toEqual({ completed: 1, total: 202 });
    expect(jobProgressTotals({
      work_units: [{ status: "running", atomic_item_count: 0, total_items: 4, completed_items: 1 }],
    })).toEqual({ completed: 1, total: 4 });
    expect(jobProgressTotals({}).total).toBe(0);
  });

  it("labels unit ETA distinctly from the job-level estimate", () => {
    expect(unitEtaLabel({ eta_s: 90 }, 600)).toBe("Unit 剩余 1 分 30 秒");
    expect(unitEtaLabel({ eta_s: null }, 3283.9)).toBe("Job 剩余约 54 分 44 秒");
    expect(unitEtaLabel({ eta_s: null }, null)).toBe("暂无 Unit 内部估计");
    expect(unitEtaLabel(null, -5)).toBe("暂无 Unit 内部估计");
  });

  it("keeps saved target capacity visible when pressure reduces effective capacity", () => {
    expect(capacityDisplay({
      effective: 1,
      target: 2,
      hardCap: 2,
      pressureState: "pressured",
    })).toEqual({
      value: "1 / 2",
      detail: "有效 1 · 目标 2 · 硬上限 2 · 压力限制",
      constrained: true,
    });
  });

  it("prefers live GPU telemetry over stale registered inventory", () => {
    const live = gpuDisplay({
      total_gpus: 0,
      metrics: { gpu: [{ name: "RTX 5060", utilization_percent: 17, available: true }] },
    });
    expect(live.inactive).toBe(false);
    expect(live.count).toBe(1);
    expect(live.detail).toContain("1 张");
    expect(live.detail).toContain("60 秒均值");
    expect(live.summary).toContain("RTX 5060");

    expect(gpuDisplay({ total_gpus: 0, metrics: { gpu: [], gpu_status: "not_detected" } }).detail)
      .toBe("未配置 GPU");
    expect(gpuDisplay({ total_gpus: 1, metrics: { gpu: [], gpu_status: "unavailable" } }).detail)
      .toBe("GPU 遥测冻结");
  });

  it("keeps GPU window average distinct from instantaneous utilization", () => {
    const gpu = gpuDisplay({
      metrics: {
        gpu: [{
          name: "RTX 4090",
          utilization_percent: 0,
          utilization_average_percent: 55.666666666664,
          available: true,
          sample_count: 8,
        }],
      },
    });
    expect(gpu.value).toBeCloseTo(55.666666666664);
    expect(gpu.average).toBe(0);
    expect(gpu.detail).toContain("60 秒均值");
    expect(gpu.tableDetail).toBe("降级 · 8 样本");
  });

  it("flags exactly the unit states the reassign flow can redirect", () => {
    const attempt = (state) => [{ state }];
    expect(unitReassignable({ status: "queued", attempts: [] })).toBe(true);
    expect(unitReassignable({ status: "running", attempt_count: 1, max_attempts: 3, attempts: attempt("running") })).toBe(true);
    expect(unitReassignable({ status: "assigned", attempts: attempt("assigned") })).toBe(true);
    expect(unitReassignable({ status: "failed_retriable", attempts: attempt("failed") })).toBe(true);
    expect(unitReassignable({ status: "cancelled", attempts: attempt("cancelled") })).toBe(true);
    // Cancellation still propagating: step two must wait.
    expect(unitReassignable({ status: "cancelled", attempts: attempt("cancel_pending") })).toBe(false);
    expect(unitReassignable({ status: "running", attempts: attempt("cancel_pending") })).toBe(false);
    // Terminal or origin-staging states are never reassignable.
    expect(unitReassignable({ status: "collecting", attempts: attempt("collecting") })).toBe(false);
    expect(unitReassignable({ status: "completed", attempts: attempt("completed") })).toBe(false);
    expect(unitReassignable({ status: "failed_terminal", attempts: attempt("failed") })).toBe(false);
    // Retries exhausted.
    expect(unitReassignable({ status: "failed_retriable", attempt_count: 3, max_attempts: 3, attempts: attempt("failed") })).toBe(false);
    expect(unitReassignable(null)).toBe(false);
  });

  it("aggregates per-machine measured durations from completed attempts only", () => {
    const job = {
      work_units: [
        {
          attempts: [
            { state: "completed", machine_id: "zlrx", started_at: "2026-08-31T08:00:00Z", finished_at: "2026-08-31T08:34:00Z" },
            { state: "running", machine_id: "yl-office", started_at: "2026-08-31T08:10:00Z" },
          ],
        },
        {
          attempts: [
            { state: "failed", machine_id: "yl-office", started_at: "2026-08-31T07:00:00Z", finished_at: "2026-08-31T08:00:00Z" },
            { state: "completed", machine_id: "yl-office", started_at: "2026-08-31T08:00:00Z", finished_at: "2026-08-31T10:00:00Z" },
          ],
        },
      ],
    };
    const durations = jobMachineDurations(job);
    expect(durations.zlrx).toEqual({ count: 1, totalMinutes: 34, maxMinutes: 34 });
    expect(durations["yl-office"]).toEqual({ count: 1, totalMinutes: 120, maxMinutes: 120 });
    // Missing or inverted timestamps never fabricate samples.
    expect(jobMachineDurations({
      work_units: [{
        attempts: [
          { state: "completed", machine_id: "m", started_at: null, finished_at: null },
          { state: "completed", machine_id: "m", started_at: "2026-08-31T09:00:00Z", finished_at: "2026-08-31T08:00:00Z" },
        ],
      }],
    })).toEqual({});
    expect(jobMachineDurations({})).toEqual({});
    expect(jobMachineDurations(null)).toEqual({});
  });

  it("derives the cumulative completion series from real timestamps only", () => {
    const job = {
      atomic_item_count: 10,
      work_units: [
        { atomic_item_count: 4, attempts: [{ state: "completed", finished_at: "2026-08-31T08:34:00Z" }] },
        { atomic_item_count: 6, attempts: [{ state: "completed", collected_at: "2026-08-31T09:10:00Z" }] },
        { atomic_item_count: 99, attempts: [{ state: "running", started_at: "2026-08-31T09:00:00Z" }] },
      ],
    };
    const series = jobCompletionSeries(job);
    expect(series).toEqual({
      denominator: 10,
      points: [
        { at: Date.parse("2026-08-31T08:34:00Z"), items: 4 },
        { at: Date.parse("2026-08-31T09:10:00Z"), items: 10 },
      ],
    });
    // Without usable timestamps the series is null - never fabricated.
    expect(jobCompletionSeries({
      work_units: [{ atomic_item_count: 5, attempts: [{ state: "completed", finished_at: null }] }],
    })).toBeNull();
    expect(jobCompletionSeries(null)).toBeNull();
    expect(jobCompletionSeries({ work_units: [] })).toBeNull();
  });

  it("builds attempt segments and the job time window from real boundaries", () => {
    const job = {
      work_units: [
        {
          attempts: [
            { state: "completed", machine_id: "zlrx", assigned_at: "2026-08-31T08:00:00Z", started_at: "2026-08-31T08:01:00Z", finished_at: "2026-08-31T08:30:00Z" },
            { state: "failed", machine_id: "yl", started_at: "2026-08-31T08:00:00Z", finished_at: "2026-08-31T08:02:00Z" },
          ],
        },
        {
          attempts: [{ state: "completed", machine_id: "yl", assigned_at: "2026-08-31T08:05:00Z", finished_at: "2026-08-31T09:00:00Z" }],
        },
      ],
    };
    const window = jobTimeWindow(job);
    expect(window).toEqual({ min: Date.parse("2026-08-31T08:00:00Z"), max: Date.parse("2026-08-31T09:00:00Z") });
    const [first, second] = attemptSegments(job.work_units[0]);
    expect(first.state).toBe("completed");
    expect(first.start).toBe(Date.parse("2026-08-31T08:00:00Z"));
    expect(second.state).toBe("failed");
    expect(jobTimeWindow({ work_units: [{ attempts: [{ state: "running", started_at: "2026-08-31T08:00:00Z" }] }] })).toBeNull();
    expect(jobTimeWindow(null)).toBeNull();
  });
});
