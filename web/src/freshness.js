// Shared lifecycle policy. Coalesce focus/visibility/pageshow/online bursts.
export const DATA_REFRESH_EVENT = "rcn:data-refresh";
export function watchPageReturn(refresh, win = window, doc = document) {
  let timer = null;
  const returned = (event) => {
    // A fresh navigation already owns its initial read. Only a restored page
    // needs pageshow revalidation; treating its first paint as return doubles it.
    if (event?.type === "pageshow" && event.persisted !== true) return;
    if (doc.visibilityState === "hidden" || timer !== null) return;
    const since = Date.now();
    timer = setTimeout(() => { timer = null; if (doc.visibilityState !== "hidden") void refresh({ since }); }, 150);
  };
  doc.addEventListener("visibilitychange", returned);
  for (const name of ["focus", "pageshow", "online"]) win.addEventListener(name, returned);
  return () => {
    clearTimeout(timer);
    doc.removeEventListener("visibilitychange", returned);
    for (const name of ["focus", "pageshow", "online"]) win.removeEventListener(name, returned);
  };
}

export function notifyDataRefresh(resources = null, reason = "manual", win = window, context = {}) {
  win.dispatchEvent(new CustomEvent(DATA_REFRESH_EVENT, { detail: { resources, reason, ...context } }));
}
