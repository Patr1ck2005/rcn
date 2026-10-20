// Bound each tab's API fan-out. Priority applies only within one enqueue turn:
// older batches keep their place, even when newer high-priority reads arrive.
export function createReadScheduler({ limit = 3, maxQueued = 128 } = {}) {
  const queue = [];
  let active = 0;
  let batch = 0;
  let sequence = 0;
  let drainScheduled = false;

  const abortReason = (signal) => signal?.reason || new DOMException("读取已取消", "AbortError");

  function scheduleDrain() {
    if (drainScheduled) return;
    drainScheduled = true;
    queueMicrotask(() => {
      drainScheduled = false;
      batch += 1;
      queue.sort((a, b) => a.batch - b.batch || a.priority - b.priority || a.sequence - b.sequence);
      while (active < limit && queue.length) {
        const entry = queue.shift();
        entry.detach();
        if (entry.signal?.aborted) {
          entry.reject(abortReason(entry.signal));
          continue;
        }
        active += 1;
        const finish = () => {
          active -= 1;
          scheduleDrain();
        };
        try {
          Promise.resolve(entry.task()).then(
            (value) => { finish(); entry.resolve(value); },
            (error) => { finish(); entry.reject(error); },
          );
        } catch (error) {
          finish();
          entry.reject(error);
        }
      }
    });
  }

  return {
    run(task, { signal, priority = 1 } = {}) {
      return new Promise((resolve, reject) => {
        if (signal?.aborted) { reject(abortReason(signal)); return; }
        if (queue.length >= maxQueued) { reject(new Error("读取请求过多，请稍后重试")); return; }
        const entry = { task, signal, priority, batch, sequence: sequence++, resolve, reject };
        const abort = () => {
          const index = queue.indexOf(entry);
          if (index < 0) return;
          queue.splice(index, 1);
          entry.detach();
          reject(abortReason(signal));
        };
        entry.detach = () => signal?.removeEventListener("abort", abort);
        signal?.addEventListener("abort", abort, { once: true });
        queue.push(entry);
        scheduleDrain();
      });
    },
    cancelQueued(reason = new DOMException("读取已取消", "AbortError")) {
      for (const entry of queue.splice(0)) {
        entry.detach();
        entry.reject(reason);
      }
    },
  };
}
