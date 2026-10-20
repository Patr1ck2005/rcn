import { afterEach, describe, expect, it, vi } from "vitest";
import { createInsightFollowup, insightSnapshotState } from "./insightRefresh";
import { createSingleFlightRefresh } from "./liveRefresh";

const snapshot = (generation = "2026-10-17T12:00:00Z", read = {}) => ({ generated_at: generation, read_state: { stale: true, refreshing: true, refresh_error: null, ...read } });
afterEach(() => vi.useRealTimers());

describe("insights last-good presentation", () => {
  it("pauses forecasts as soon as the server marks a snapshot stale without changing its time", () => {
    const data = snapshot(), generatedAt = data.generated_at;
    const state = insightSnapshotState(data, "", { now: Date.parse(generatedAt) + 16000 });
    expect(state.stale).toBe(true); expect(state.message).toContain("后台更新");
    expect(data.generated_at).toBe(generatedAt);
    expect(insightSnapshotState(snapshot(generatedAt, { stale: false, refreshing: false }), "", { now: Date.parse(generatedAt) + 1000 }).stale).toBe(false);
  });
  it("distinguishes background failure, transport failure and an exhausted wait", () => {
    expect(insightSnapshotState(snapshot(undefined, { refreshing: false, refresh_error: "RuntimeError" })).message).toContain("后台更新失败");
    expect(insightSnapshotState(snapshot(), "connection failed").error).toBe("connection failed");
    expect(insightSnapshotState(snapshot(), "", { followupExpired: true }).message).toContain("已回到普通刷新");
    expect(insightSnapshotState({ generated_at: "2000-01-01T00:00:00Z" }).stale).toBe(true);
  });
});

describe("bounded insights background follow-up", () => {
  it("follows through the existing single-flight coordinator and stops on a new generation", async () => {
    vi.useFakeTimers();
    let release, followup;
    const read = vi.fn(async () => {
      await new Promise((resolve) => { release = resolve; });
      followup.observe(snapshot("2026-10-17T12:00:01Z", { stale: false, refreshing: false }));
    });
    const coordinator = createSingleFlightRefresh(read);
    followup = createInsightFollowup(coordinator.run, { random: () => 0 });
    const operation = coordinator.run();
    followup.observe(snapshot());
    await vi.advanceTimersByTimeAsync(3000);
    expect(read).toHaveBeenCalledTimes(1); // Follow-up joins this slow read.
    release(); await operation;
    await vi.advanceTimersByTimeAsync(3000);
    expect(read).toHaveBeenCalledTimes(1);
    followup.dispose(); coordinator.dispose();
  });
  it("reads a refreshing generation until it becomes fresh, never concurrently", async () => {
    vi.useFakeTimers();
    let followup, active = 0, peak = 0;
    const refresh = vi.fn(async () => {
      active += 1; peak = Math.max(peak, active);
      followup.observe(refresh.mock.calls.length < 2 ? snapshot() : snapshot("2026-10-17T12:00:01Z", { stale: false, refreshing: false }));
      active -= 1;
    });
    followup = createInsightFollowup(refresh, { random: () => 0 });
    followup.observe(snapshot());
    await vi.advanceTimersByTimeAsync(2000);
    expect(refresh).toHaveBeenCalledTimes(2); expect(peak).toBe(1);
    expect(refresh.mock.calls.every(([request]) => request.join && request.reason === "insight-followup")).toBe(true);
    followup.dispose();
  });
  it("stops at the deadline and cannot restart that generation after ordinary refreshes", async () => {
    vi.useFakeTimers();
    const refresh = vi.fn().mockResolvedValue(undefined), expired = vi.fn();
    const followup = createInsightFollowup(refresh, { random: () => 0, onExpired: expired });
    followup.observe(snapshot());
    await vi.advanceTimersByTimeAsync(15000);
    expect(refresh).toHaveBeenCalledTimes(29); expect(expired).toHaveBeenCalledExactlyOnceWith(true);
    followup.observe(snapshot());
    await vi.advanceTimersByTimeAsync(30000);
    expect(refresh).toHaveBeenCalledTimes(29);
    followup.observe(snapshot("2026-10-17T12:00:02Z"));
    await vi.advanceTimersByTimeAsync(500);
    expect(refresh).toHaveBeenCalledTimes(30); expect(expired).toHaveBeenLastCalledWith(false);
    followup.dispose();
  });
  it("stops immediately on background failure without restarting its failed generation", async () => {
    vi.useFakeTimers();
    let followup;
    const refresh = vi.fn(async () => followup.observe(snapshot(undefined, { refreshing: false, refresh_error: "RuntimeError" })));
    followup = createInsightFollowup(refresh, { random: () => 0 });
    followup.observe(snapshot());
    await vi.advanceTimersByTimeAsync(5000);
    expect(refresh).toHaveBeenCalledTimes(1);
    followup.observe(snapshot()); // Ordinary retry cannot reopen rapid reads.
    await vi.advanceTimersByTimeAsync(5000);
    expect(refresh).toHaveBeenCalledTimes(1);
    followup.dispose();
  });
  it("respects hidden pages, disposal, and transport failures", async () => {
    vi.useFakeTimers();
    let visible = false;
    const refresh = vi.fn().mockResolvedValue(undefined);
    const followup = createInsightFollowup(refresh, { random: () => 0, isVisible: () => visible });
    followup.observe(snapshot()); await vi.advanceTimersByTimeAsync(1000);
    expect(refresh).not.toHaveBeenCalled();
    visible = true; followup.observe(snapshot()); await vi.advanceTimersByTimeAsync(500);
    expect(refresh).toHaveBeenCalledTimes(1);
    followup.fail(); await vi.advanceTimersByTimeAsync(2000);
    expect(refresh).toHaveBeenCalledTimes(1);
    followup.observe(snapshot("2026-10-17T12:00:03Z")); followup.dispose();
    await vi.advanceTimersByTimeAsync(1000);
    expect(refresh).toHaveBeenCalledTimes(1);
  });
});
