export function insightSnapshotState(data, error = "", { now = Date.now(), followupExpired = false } = {}) {
  const read = data?.read_state;
  const at = Date.parse(data?.generated_at);
  const stale = Boolean(error || read?.stale) || !Number.isFinite(at) || now - at > 45000;
  const refreshError = read?.refresh_error;
  let message = "";
  if (stale) {
    message = refreshError ? "后台更新失败；保留上次图表，暂停完工预测。"
      : error ? "数据更新失败；保留上次图表，暂停完工预测。"
        : followupExpired ? "后台更新仍未完成，已回到普通刷新；保留上次图表，暂停完工预测。"
          : read?.refreshing ? "统计正在后台更新；保留上次图表，暂停完工预测。"
            : "统计快照已过期；保留上次图表，暂停完工预测。";
  }
  return { stale, message, error: error || refreshError || "" };
}

// Wait briefly for one generation's background refresh. Every request goes
// through the page's existing coordinator; no independent fetch or catch-up.
export function createInsightFollowup(refresh, {
  maxWaitMs = 15000, random = Math.random, now = Date.now,
  setTimer = setTimeout, clearTimer = clearTimeout,
  isVisible = () => true, onExpired = () => {},
} = {}) {
  let timer = null, running = false, stopped = false;
  let snapshot = null, generation = null, deadline = 0, blocked = false, expired = false;
  const clear = () => { if (timer !== null) clearTimer(timer); timer = null; };
  const arm = () => {
    if (stopped || timer !== null || running || blocked || !snapshot?.read_state?.stale || !snapshot.read_state.refreshing || snapshot.read_state.refresh_error) return;
    const remaining = deadline - now();
    if (remaining <= 0) {
      blocked = true; expired = true; onExpired(true); return;
    }
    if (!isVisible()) return;
    timer = setTimer(async () => {
      timer = null;
      if (stopped || !isVisible()) return;
      if (now() >= deadline) { arm(); return; }
      running = true;
      try { await refresh({ reason: "insight-followup", join: true }); }
      catch { blocked = true; }
      finally { running = false; arm(); }
    }, Math.min(500 + 250 * random(), remaining));
  };
  return {
    observe(data) {
      if (stopped) return;
      snapshot = data;
      if (data.generated_at !== generation) {
        clear(); generation = data.generated_at; deadline = now() + maxWaitMs; blocked = false;
        if (expired) { expired = false; onExpired(false); }
      }
      if (!data.read_state?.stale || !data.read_state.refreshing || data.read_state.refresh_error) {
        clear();
        if (data.read_state?.refresh_error) blocked = true;
        return;
      }
      arm();
    },
    fail() { clear(); blocked = true; },
    dispose() { stopped = true; clear(); },
  };
}
