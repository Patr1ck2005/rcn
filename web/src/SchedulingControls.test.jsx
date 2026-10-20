import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { SmallBatchLimits, parallelBatchEnabled, policyChange, smallBatchThresholdText, strategies, supportsParallelBatch } from "./SchedulingControls";

describe("audited scheduling UI contract", () => {
  it("offers the explicit small-batch option without a silent strategy switch", () => {
    expect(strategies.map(([id]) => id)).toEqual(["balanced", "small_batch_first", "throughput"]);
  });
  it("freezes a new request without mutating the current policy", () => {
    const snapshot = { revision: 4 }, draft = { strategy: "small_batch_first", starvation_after_s: 7200 };
    const result = policyChange(snapshot, draft, "  lab small batch policy  ");
    draft.strategy = "balanced";
    expect(result).toEqual({ expected_revision: 4, policy: { strategy: "small_batch_first", starvation_after_s: 7200 }, reason: "lab small batch policy" });
  });
  it("requires a reason and loaded authority snapshot", () => {
    expect(() => policyChange(null, {}, "why")).toThrow();
    expect(() => policyChange({ revision: 0 }, {}, " ")).toThrow();
  });
  it("retains an active parallel threshold and all legacy fields through preview and confirmation", () => {
    const policy = { strategy: "small_batch_first", small_batch_max_units: 4,
      small_batch_max_serial_seconds: 1800, small_batch_max_parallel_seconds: 2460, starvation_after_s: 7200 };
    const request = policyChange({ revision: 6, policy, parallel_small_batch_schema: 1 }, policy, "parallel completion rule");
    policy.small_batch_max_parallel_seconds = 3000;
    const pending = { ...request, confirmation_hash: "frozen-confirmation" };
    expect(JSON.parse(JSON.stringify(pending)).policy).toEqual({ strategy: "small_batch_first",
      small_batch_max_units: 4, small_batch_max_serial_seconds: 1800,
      small_batch_max_parallel_seconds: 2460, starvation_after_s: 7200 });
  });
  it("recognizes explicit capability or an existing parallel field, with old API fallback", () => {
    expect(supportsParallelBatch({ policy: {} })).toBe(false);
    expect(supportsParallelBatch({ parallel_small_batch_schema: 1, policy: {} })).toBe(true);
    expect(supportsParallelBatch({ policy: { small_batch_max_parallel_seconds: null } })).toBe(true);
    expect(supportsParallelBatch({ policy: { small_batch_max_parallel_seconds: 2460 } })).toBe(true);
  });
  it("shows editable 41 minutes and hides unused legacy thresholds in parallel mode", () => {
    const policy = { small_batch_max_units: 4, small_batch_max_serial_seconds: 1800,
      small_batch_max_parallel_seconds: 2460, starvation_after_s: 7200 };
    const markup = renderToStaticMarkup(<SmallBatchLimits draft={policy} disabled={false} supportsParallel onChange={() => {}} />);
    expect(markup).toContain("小批量并行完工上限（分钟）");
    expect(markup).toContain('value="41"');
    expect(markup).not.toContain("小批量最多单元数");
    expect(markup).not.toContain("小批量总预计时长上限");
    expect(smallBatchThresholdText(policy)).toBe("并行完工上限 41 分钟（最大兼容容量）");
  });
  it("keeps legacy controls and wire shape when the old API lacks the new field", () => {
    const policy = { small_batch_max_units: 4, small_batch_max_serial_seconds: 1800, starvation_after_s: 7200 };
    const markup = renderToStaticMarkup(<SmallBatchLimits draft={policy} disabled={false} supportsParallel={false} onChange={() => {}} />);
    expect(markup).toContain("小批量最多单元数");
    expect(markup).toContain("小批量总预计时长上限（秒）");
    expect(markup).not.toContain("小批量判定方式");
    expect(policyChange({ revision: 1 }, policy, "legacy").policy).not.toHaveProperty("small_batch_max_parallel_seconds");
    expect(parallelBatchEnabled({ small_batch_max_parallel_seconds: null })).toBe(false);
  });
  it("rejects out-of-range or fractional-second parallel thresholds before preview", () => {
    for (const seconds of [0, 59, 86401, 2460.5, NaN]) {
      expect(() => policyChange({ revision: 1 }, { small_batch_max_parallel_seconds: seconds }, "bounds")).toThrow("整秒");
    }
    expect(policyChange({ revision: 1 }, { small_batch_max_parallel_seconds: 2490 }, "41.5 minutes").policy.small_batch_max_parallel_seconds).toBe(2490);
  });
});
