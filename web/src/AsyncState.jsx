import { AlertTriangle, LoaderCircle, RotateCw } from "lucide-react";

export const initialRequestState = (keys) => Object.fromEntries(
  keys.map((key) => [key, { status: "loading", error: "" }]),
);

export const settleResourceRequests = (keys, request, onValue, onError) => Promise.allSettled(
  keys.map(async (key) => {
    try {
      const value = await request(key);
      onValue(key, value);
      return value;
    } catch (error) {
      onError(key, error);
      throw error;
    }
  }),
);

export function DataLoadState({ label = "正在加载内容", error = "", onRetry, compact = false }) {
  if (error) {
    return <div className={`data-state data-state-error ${compact ? "compact" : ""}`} role="alert">
      <AlertTriangle size={18} />
      <span><b>内容暂时不可用</b><small>{error}</small></span>
      {onRetry && <button className="button small" onClick={onRetry}><RotateCw size={14} />重试</button>}
    </div>;
  }
  return <div className={`data-state ${compact ? "compact" : ""}`} role="status" aria-live="polite" aria-label={label}>
    <LoaderCircle size={19} className="spin" aria-hidden="true" />
    <span>{label}</span>
  </div>;
}

export function RefreshStatus({ visible, label = "正在更新" }) {
  if (!visible) return null;
  return <span className="refresh-status" role="status" aria-live="polite">
    <LoaderCircle size={13} className="spin" aria-hidden="true" />{label}
  </span>;
}
