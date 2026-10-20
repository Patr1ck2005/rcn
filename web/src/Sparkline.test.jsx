import { describe, expect, it } from "vitest";
import { sparklineSegments } from "./Sparkline";

describe("sparkline telemetry gaps", () => {
  it("does not connect across a stale telemetry interval", () => {
    const start = Date.parse("2026-08-16T00:00:00Z");
    const samples = [0, 15, 30, 120, 135].map((seconds, index) => ({
      recorded_at: new Date(start + seconds * 1000).toISOString(),
      metrics: { cpu_total_percent: index * 10 },
    }));
    const segments = sparklineSegments(samples, (sample) => sample.metrics.cpu_total_percent);
    expect(segments).toHaveLength(2);
    expect(segments.map((segment) => segment.length)).toEqual([3, 2]);
  });
});
