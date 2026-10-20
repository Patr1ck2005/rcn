export function createRefreshCoalescer(
  refresh,
  { delayMs = 250, setTimer = setTimeout, clearTimer = clearTimeout, isVisible = () => true } = {},
) {
  let timer = null;
  let dirty = false;
  let stopped = false;
  let running = null;

  const arm = () => {
    if (stopped || running || timer !== null || !isVisible()) return;
    timer = setTimer(() => {
      timer = null;
      void run().catch(() => {});
    }, delayMs);
  };

  const run = async () => {
    if (stopped || running || !dirty || !isVisible()) return running;
    if (timer !== null) {
      clearTimer(timer);
      timer = null;
    }
    dirty = false;
    running = Promise.resolve().then(refresh);
    try {
      await running;
    } finally {
      running = null;
      if (dirty) arm();
    }
  };

  return {
    schedule() {
      if (stopped) return;
      dirty = true;
      arm();
    },
    async flush() {
      if (stopped) return;
      dirty = true;
      if (timer !== null) {
        clearTimer(timer);
        timer = null;
      }
      if (running) {
        await running;
      }
      if (dirty) await run();
    },
    cancel() {
      stopped = true;
      dirty = false;
      if (timer !== null) clearTimer(timer);
      timer = null;
    },
  };
}

// One active read and at most one trailing read. Disposing a route aborts its
// requests and invalidates every commit, even when a transport ignores abort.
export function createSingleFlightRefresh(refresh, { isVisible = () => true, now = Date.now } = {}) {
  let running = null, pending = null, stopped = false;
  let lastStartedAt = -Infinity, lastResources = null;
  const controller = new AbortController();
  const context = { signal: controller.signal, isCurrent: () => !stopped };
  const run = (request = {}) => {
    if (stopped) return Promise.resolve();
    const resources = Array.isArray(request.resources) ? request.resources : null;
    // A poll that started after this return event already covered the return,
    // including when it finishes before the 150ms event burst settles.
    const covered = lastResources === null || resources !== null && resources.every((item) => lastResources.includes(item));
    if (request.reason === "return" && Number.isFinite(request.since) && lastStartedAt >= request.since && covered) return running || Promise.resolve();
    if (running && request.join) return running;
    pending = pending ? {
      resources: pending.resources && resources ? [...new Set([...pending.resources, ...resources])] : null,
      reason: pending.reason === "initial" || request.reason === "initial" ? "initial" : request.reason || "manual",
      since: request.since ?? pending.since,
    } : { resources, reason: request.reason || "manual", since: request.since };
    if (running) return running;
    if (!isVisible()) return Promise.resolve();
    running = (async () => {
      do {
        const batch = pending; pending = null;
        lastStartedAt = now(); lastResources = batch.resources;
        try { await refresh({ ...context, ...batch }); }
        catch { /* Each resource presents its own error; no unhandled timer rejection. */ }
      } while (pending && !stopped && isVisible());
    })().finally(() => { running = null; });
    return running;
  };
  return { run, dispose() { stopped = true; pending = null; controller.abort(); } };
}

// Spread independent tabs' deadlines without changing the mean poll interval.
// A poll joins an existing read rather than making it dirty for another round.
export function createRefreshPoller(refresh, intervalMs, { random = Math.random, now = Date.now, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  let stopped = false, timer = null;
  const arm = (elapsed = 0) => {
    if (stopped) return;
    const period = intervalMs * (0.9 + random() * 0.2);
    let delay = period - elapsed;
    // A read slower than the period already covered the missed deadlines.
    // Resume at a future deadline instead of spinning catch-up requests.
    if (delay <= 0) delay += Math.ceil((1 - delay) / intervalMs) * intervalMs;
    timer = setTimer(async () => {
      const started = now();
      try { await refresh({ reason: "poll", join: true }); }
      catch { /* The next deadline still retries a failed read. */ }
      finally { arm(now() - started); }
    }, delay);
  };
  arm();
  return () => { stopped = true; clearTimer(timer); };
}

// Establish the stream cursor before starting the first snapshot, when the
// stream is available. Failure or a short bounded wait releases normal reads.
export function createStartupBaseline({ timeoutMs = 250, setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  let settled = false, release;
  const ready = new Promise((resolve) => { release = resolve; });
  const resolve = () => { if (settled) return false; settled = true; clearTimer(timer); release(); return true; };
  const timer = setTimer(resolve, timeoutMs);
  return { ready, establish: resolve, release: resolve };
}
