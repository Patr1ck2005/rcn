import { useCallback, useEffect, useRef } from "react";
import { DATA_REFRESH_EVENT } from "./freshness";
import { createRefreshPoller, createSingleFlightRefresh } from "./liveRefresh";

// Keep callback current without resetting component state or an editor draft.
export function usePageRefresh(callback, { key = "", initial = false, intervalMs = 0, enabled = true, listen = true, resources = null } = {}) {
  const latest = useRef(callback);
  latest.current = callback;
  const subscribed = useRef(resources);
  subscribed.current = resources;
  const runner = useRef(null);
  const refresh = useCallback((request = {}) => runner.current?.run(request) || Promise.resolve(), []);
  useEffect(() => {
    if (!enabled) return undefined;
    const coordinator = createSingleFlightRefresh((context) => latest.current(context), {
      isVisible: () => document.visibilityState !== "hidden",
    });
    runner.current = coordinator;
    const invalidated = (event) => {
      const affected = event.detail?.resources;
      if (Array.isArray(affected) && subscribed.current && !affected.some((resource) => subscribed.current.includes(resource))) return;
      const reason = event.detail?.reason || "event";
      void refresh({ reason, resources: affected, since: event.detail?.since, join: reason === "poll" });
    };
    if (listen) window.addEventListener(DATA_REFRESH_EVENT, invalidated);
    const stopPolling = intervalMs ? createRefreshPoller(refresh, intervalMs) : () => {};
    if (initial) void refresh({ reason: "initial" });
    return () => {
      coordinator.dispose();
      if (runner.current === coordinator) runner.current = null;
      stopPolling();
      window.removeEventListener(DATA_REFRESH_EVENT, invalidated);
    };
  }, [key, initial, intervalMs, enabled, listen, refresh]);
  return refresh;
}
