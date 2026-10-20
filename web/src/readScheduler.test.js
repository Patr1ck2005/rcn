import { describe, expect, it, vi } from "vitest";
import { createReadScheduler } from "./readScheduler";

const flush = async () => { for (let i = 0; i < 6; i += 1) await Promise.resolve(); };
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

describe("read scheduler", () => {
  it("caps active reads at three and prioritizes a same-turn burst", async () => {
    const scheduler = createReadScheduler();
    const started = [];
    const gates = Array.from({ length: 6 }, deferred);
    const priorities = [2, 1, 0, 2, 1, 2];
    const reads = priorities.map((priority, id) => scheduler.run(() => {
      started.push(id);
      return gates[id].promise;
    }, { priority }));
    expect(started).toEqual([]);
    await flush();
    expect(started).toEqual([2, 1, 4]);
    gates[2].resolve();
    await flush();
    expect(started).toEqual([2, 1, 4, 0]);
    gates.forEach((gate) => gate.resolve());
    await Promise.all(reads);
    expect(started).toEqual([2, 1, 4, 0, 3, 5]);
  });

  it("keeps older normal reads ahead of newer priority batches", async () => {
    const scheduler = createReadScheduler({ limit: 1 });
    const first = deferred();
    const started = [];
    const active = scheduler.run(() => { started.push("active"); return first.promise; });
    const old = scheduler.run(() => { started.push("old-normal"); }, { priority: 2 });
    await flush();
    const newer = scheduler.run(() => { started.push("new-priority"); }, { priority: 0 });
    await flush();
    const newest = scheduler.run(() => { started.push("newest-priority"); }, { priority: 0 });
    first.resolve();
    await Promise.all([active, old, newer, newest]);
    expect(started).toEqual(["active", "old-normal", "new-priority", "newest-priority"]);
  });

  it("removes aborted queued reads without occupying or leaking a slot", async () => {
    const scheduler = createReadScheduler({ limit: 1 });
    const gate = deferred();
    const active = scheduler.run(() => gate.promise);
    await flush();
    const controller = new AbortController();
    const task = vi.fn();
    const aborted = expect(scheduler.run(task, { signal: controller.signal })).rejects.toThrow("cancel queued");
    controller.abort(new Error("cancel queued"));
    await aborted;
    const successor = vi.fn();
    const next = scheduler.run(successor);
    gate.resolve();
    await Promise.all([active, next]);
    expect(task).not.toHaveBeenCalled();
    expect(successor).toHaveBeenCalledOnce();
  });

  it("releases slots after synchronous and asynchronous failures", async () => {
    const scheduler = createReadScheduler({ limit: 1 });
    const sync = expect(scheduler.run(() => { throw new Error("sync failure"); })).rejects.toThrow("sync failure");
    const async = expect(scheduler.run(() => Promise.reject(new Error("async failure")))).rejects.toThrow("async failure");
    const next = scheduler.run(() => "success");
    await Promise.all([sync, async]);
    await expect(next).resolves.toBe("success");
  });

  it("bounds pending memory and allows reuse after canceling the queue", async () => {
    const scheduler = createReadScheduler({ limit: 1, maxQueued: 2 });
    const gate = deferred();
    const active = scheduler.run(() => gate.promise);
    await flush();
    const first = expect(scheduler.run(vi.fn())).rejects.toThrow("identity changed");
    const second = expect(scheduler.run(vi.fn())).rejects.toThrow("identity changed");
    const overflow = expect(scheduler.run(vi.fn())).rejects.toThrow("读取请求过多");
    scheduler.cancelQueued(new Error("identity changed"));
    await Promise.all([first, second, overflow]);
    const fresh = scheduler.run(() => "fresh");
    gate.resolve();
    await active;
    await expect(fresh).resolves.toBe("fresh");
  });
});
