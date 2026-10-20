import { describe, expect, it, vi } from "vitest";

import { createRefreshCoalescer, createRefreshPoller, createSingleFlightRefresh, createStartupBaseline } from "./liveRefresh";

describe("live refresh coalescing", () => {
  it("collapses a burst of state events into one refresh", async () => {
    vi.useFakeTimers();
    const refresh = vi.fn().mockResolvedValue(undefined);
    const coalescer = createRefreshCoalescer(refresh);

    coalescer.schedule();
    coalescer.schedule();
    coalescer.schedule();
    await vi.advanceTimersByTimeAsync(250);

    expect(refresh).toHaveBeenCalledTimes(1);
    coalescer.cancel();
    vi.useRealTimers();
  });

  it("runs one follow-up refresh when an event arrives during a refresh", async () => {
    vi.useFakeTimers();
    let release;
    const refresh = vi.fn()
      .mockImplementationOnce(() => new Promise((resolve) => { release = resolve; }))
      .mockResolvedValue(undefined);
    const coalescer = createRefreshCoalescer(refresh);

    coalescer.schedule();
    await vi.advanceTimersByTimeAsync(250);
    coalescer.schedule();
    release();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(250);

    expect(refresh).toHaveBeenCalledTimes(2);
    coalescer.cancel();
    vi.useRealTimers();
  });

  it("flushes a sequence gap immediately and cancels the delayed refresh", async () => {
    vi.useFakeTimers();
    const refresh = vi.fn().mockResolvedValue(undefined);
    const coalescer = createRefreshCoalescer(refresh);

    coalescer.schedule();
    await coalescer.flush();
    await vi.advanceTimersByTimeAsync(250);

    expect(refresh).toHaveBeenCalledTimes(1);
    coalescer.cancel();
    vi.useRealTimers();
  });
});


describe("single-flight page generations", () => {
  it.each([false, true])("coalesces a return with a covering poll that has already started (completed=%s)", async (completed) => {
    let time = 110, release;
    const refresh = vi.fn(() => new Promise((resolve) => { release = resolve; }));
    const runner = createSingleFlightRefresh(refresh, { now: () => time });
    const poll = runner.run({ reason: "poll" });
    if (completed) { release(); await poll; }
    time = 150;
    const returned = runner.run({ reason: "return", since: 100 });
    if (!completed) { expect(returned).toBe(poll); release(); }
    await returned;
    expect(refresh).toHaveBeenCalledTimes(1); runner.dispose();
  });
  it("keeps one fresh return after an old read that began before visibility returned", async () => {
    let time = 90, release;
    const refresh = vi.fn().mockImplementationOnce(() => new Promise((resolve) => { release = resolve; })).mockResolvedValue(undefined);
    const runner = createSingleFlightRefresh(refresh, { now: () => time });
    const original = runner.run({ reason: "poll" });
    time = 150; runner.run({ reason: "return", since: 100 }); release(); await original;
    expect(refresh).toHaveBeenCalledTimes(2);
    expect(refresh.mock.calls[1][0]).toMatchObject({ reason: "return", resources: null }); runner.dispose();
  });
  it("does not let a partial state read swallow a full page return", async () => {
    let time = 110, release;
    const refresh = vi.fn().mockImplementationOnce(() => new Promise((resolve) => { release = resolve; })).mockResolvedValue(undefined);
    const runner = createSingleFlightRefresh(refresh, { now: () => time });
    const original = runner.run({ reason: "state", resources: ["jobs"] });
    time = 150; runner.run({ reason: "return", since: 100 }); release(); await original;
    expect(refresh).toHaveBeenCalledTimes(2);
    expect(refresh.mock.calls[1][0]).toMatchObject({ reason: "return", resources: null }); runner.dispose();
  });
  it("retains real state events queued during a poll when return joins that poll", async () => {
    let time = 110, release;
    const refresh = vi.fn().mockImplementationOnce(() => new Promise((resolve) => { release = resolve; })).mockResolvedValue(undefined);
    const runner = createSingleFlightRefresh(refresh, { now: () => time });
    const original = runner.run({ reason: "poll" });
    runner.run({ reason: "state", resources: ["jobs"] });
    time = 150; expect(runner.run({ reason: "return", since: 100 })).toBe(original);
    release(); await original;
    expect(refresh).toHaveBeenCalledTimes(2);
    expect(refresh.mock.calls[1][0]).toMatchObject({ reason: "state", resources: ["jobs"] }); runner.dispose();
  });
  it("joins an initial baseline and polls but retains a real event during that read", async () => {
    let release;
    const refresh = vi.fn().mockImplementationOnce(() => new Promise((resolve) => { release = resolve; })).mockResolvedValue(undefined);
    const runner = createSingleFlightRefresh(refresh);
    const operation = runner.run({ reason: "initial" });
    expect(runner.run({ reason: "initial", join: true })).toBe(operation);
    expect(runner.run({ reason: "poll", join: true })).toBe(operation);
    runner.run({ reason: "state", resources: ["jobs"] });
    runner.run({ reason: "state", resources: ["jobs", "insights"] });
    release(); await operation;
    expect(refresh).toHaveBeenCalledTimes(2);
    expect(refresh.mock.calls[1][0]).toMatchObject({ reason: "state", resources: ["jobs", "insights"] });
    runner.dispose();
  });
  it("does not queue another round when only a baseline or poll joins", async () => {
    let release;
    const refresh = vi.fn(() => new Promise((resolve) => { release = resolve; }));
    const runner = createSingleFlightRefresh(refresh);
    const operation = runner.run({ reason: "initial" });
    runner.run({ reason: "initial", join: true }); runner.run({ reason: "poll", join: true });
    release(); await operation;
    expect(refresh).toHaveBeenCalledTimes(1);
    runner.dispose();
  });
  it("collapses concurrent triggers into one trailing read", async () => {
    let release;
    const refresh = vi.fn().mockImplementationOnce(() => new Promise((resolve) => { release = resolve; })).mockResolvedValue(undefined);
    const runner = createSingleFlightRefresh(refresh);
    const operation = runner.run(); runner.run(); runner.run();
    expect(refresh).toHaveBeenCalledTimes(1);
    release(); await operation;
    expect(refresh).toHaveBeenCalledTimes(2);
    runner.dispose();
  });
  it("pauses hidden reads and performs the pending read on return", async () => {
    let visible = false;
    const refresh = vi.fn().mockResolvedValue(undefined);
    const runner = createSingleFlightRefresh(refresh, { isVisible: () => visible });
    await runner.run(); await runner.run();
    expect(refresh).not.toHaveBeenCalled();
    visible = true; await runner.run();
    expect(refresh).toHaveBeenCalledTimes(1);
    runner.dispose();
  });
  it("aborts and invalidates a former route even when its request completes late", async () => {
    let context, release;
    const committed = vi.fn();
    const runner = createSingleFlightRefresh(async (scope) => {
      context = scope; await new Promise((resolve) => { release = resolve; });
      if (scope.isCurrent()) committed();
    });
    const operation = runner.run(); runner.run(); runner.dispose();
    expect(context.signal.aborted).toBe(true);
    release(); await operation;
    expect(committed).not.toHaveBeenCalled();
  });
});

describe("startup and polling deadlines", () => {
  it("releases the first snapshot at the stream cursor or bounded fallback", async () => {
    vi.useFakeTimers();
    const startup = createStartupBaseline();
    const ready = vi.fn(); startup.ready.then(ready);
    await vi.advanceTimersByTimeAsync(200);
    expect(ready).not.toHaveBeenCalled();
    expect(startup.establish()).toBe(true);
    await startup.ready;
    expect(ready).toHaveBeenCalledTimes(1);
    expect(startup.establish()).toBe(false);
    const fallback = createStartupBaseline();
    const fallbackReady = vi.fn(); fallback.ready.then(fallbackReady);
    await vi.advanceTimersByTimeAsync(250);
    expect(fallbackReady).toHaveBeenCalledTimes(1);
    expect(fallback.establish()).toBe(false);
    const failed = createStartupBaseline();
    expect(failed.release()).toBe(true);
    await failed.ready;
    expect(vi.getTimerCount()).toBe(0);
    vi.useRealTimers();
  });
  it("spreads tab deadlines, joins an in-flight read and cancels future polls", async () => {
    vi.useFakeTimers();
    const first = vi.fn().mockResolvedValue(undefined), second = vi.fn().mockResolvedValue(undefined);
    const stopFirst = createRefreshPoller(first, 15000, { random: () => 0 });
    const stopSecond = createRefreshPoller(second, 15000, { random: () => 1 });
    await vi.advanceTimersByTimeAsync(13499);
    expect(first).not.toHaveBeenCalled(); expect(second).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(first).toHaveBeenCalledExactlyOnceWith({ reason: "poll", join: true });
    expect(second).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(3000);
    expect(second).toHaveBeenCalledExactlyOnceWith({ reason: "poll", join: true });
    stopFirst(); stopSecond();
    await vi.advanceTimersByTimeAsync(30000);
    expect(first).toHaveBeenCalledTimes(1); expect(second).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });
  it("skips elapsed deadlines after a slow read rather than polling in a catch-up loop", async () => {
    vi.useFakeTimers();
    let release;
    const refresh = vi.fn().mockImplementationOnce(() => new Promise((resolve) => { release = resolve; })).mockResolvedValue(undefined);
    const stop = createRefreshPoller(refresh, 15000, { random: () => 0.5 });
    await vi.advanceTimersByTimeAsync(15000);
    await vi.advanceTimersByTimeAsync(45000);
    expect(refresh).toHaveBeenCalledTimes(1);
    release(); await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(14999);
    expect(refresh).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(refresh).toHaveBeenCalledTimes(2);
    stop(); vi.useRealTimers();
  });
});
