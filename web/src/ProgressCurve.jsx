import { memo } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

// Real-data completion trajectory: a step curve from 0 to 100% built from
// per-unit completion timestamps. No interpolation, no fabricated points.
export const CompletionCurve = memo(function CompletionCurve({ series, height = 170 }) {
  if (!series || !series.points.length) {
    return <p className="curve-empty">暂无可回放的完成数据（需要单元完成时间戳）。</p>;
  }
  const data = series.points.map((point) => ({
    at: point.at,
    pct: Math.min(100, Math.round(point.items / series.denominator * 100)),
    items: point.items,
  }));
  return <div className="curve-body" style={{ height }}>
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 8, right: 16, left: -14, bottom: 0 }}>
        <CartesianGrid stroke="var(--line)" vertical={false} />
        <XAxis
          dataKey="at"
          type="number"
          domain={["dataMin", "dataMax"]}
          tickFormatter={(value) => new Date(value).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" })}
          minTickGap={42}
        />
        <YAxis domain={[0, 100]} width={44} tickFormatter={(value) => `${value}%`} />
        <Tooltip
          labelFormatter={(value) => new Date(value).toLocaleString("zh-CN", { hour12: false })}
          formatter={(value, name, entry) => [`${value}%（${entry?.payload?.items ?? "-"} 原子项）`, "累计完成"]}
        />
        <Area type="stepAfter" dataKey="pct" stroke="var(--cyan)" fill="var(--cyan-soft)" strokeWidth={1.8} dot={false} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  </div>;
});

// Lightweight card sparkline: same real data, plain SVG polyline (no chart
// library cost per card).
export const MiniSpark = memo(function MiniSpark({ series, width = 120, height = 26 }) {
  if (!series || series.points.length < 2) return null;
  const points = series.points;
  const tMin = points[0].at;
  const tMax = points[points.length - 1].at;
  const span = tMax > tMin ? tMax - tMin : 1;
  const path = [[0, height]].concat(points.map((point) => [
    ((point.at - tMin) / span) * width,
    height - Math.min(100, point.items / series.denominator * 100) / 100 * height,
  ])).concat([[width, height]]);
  return <svg className="mini-spark" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden="true">
    <polygon points={path.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ")} className="mini-spark-fill" />
    <polyline points={path.slice(1, -1).map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ")} className="mini-spark-line" />
  </svg>;
});

// Per-unit attempt bars on the job's real time window: one segment per
// attempt, positioned by its actual start/end, colored by outcome.
export const AttemptTimeline = memo(function AttemptTimeline({ segments, window: timeWindow, height = 8 }) {
  if (!timeWindow || !segments.length) return null;
  const span = timeWindow.max - timeWindow.min;
  return <svg className="attempt-timeline" viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" aria-hidden="true">
    {segments.map((segment, index) => <rect
      key={index}
      x={((segment.start - timeWindow.min) / span * 100).toFixed(2)}
      y={1}
      width={Math.max(0.8, (segment.end - segment.start) / span * 100).toFixed(2)}
      height={height - 2}
      className={`tl-seg tl-${segment.state}`}
    >
      <title>{`${segment.machine || "未知机器"} · ${segment.state}`}</title>
    </rect>)}
  </svg>;
});
