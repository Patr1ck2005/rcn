export function sparklineSegments(samples, selector) {
  const pointsWithTime = samples
    .map((sample) => ({ value: selector(sample), time: new Date(sample.recorded_at).getTime() }))
    .filter(({ value, time }) => Number.isFinite(value) && Number.isFinite(time));
  const values = pointsWithTime.map(({ value }) => value);
  if (values.length < 2) return [];
  const low = Math.min(...values);
  const high = Math.max(...values);
  const span = Math.max(high - low, 1);
  const deltas = pointsWithTime.slice(1).map((point, index) => point.time - pointsWithTime[index].time).filter((value) => value > 0);
  const typicalDelta = deltas.length ? Math.min(...deltas) : 15000;
  const gapThreshold = Math.max(typicalDelta * 3, 45000);
  const start = pointsWithTime[0].time;
  const duration = Math.max(pointsWithTime.at(-1).time - start, 1);
  const segments = [[]];
  pointsWithTime.forEach((point, index) => {
    if (index && point.time - pointsWithTime[index - 1].time > gapThreshold) segments.push([]);
    segments.at(-1).push(`${((point.time - start) / duration) * 100},${94 - ((point.value - low) / span) * 82}`);
  });
  return segments.filter((segment) => segment.length > 1);
}

export function Sparkline({ samples, selector, color = "#39d98a" }) {
  const segments = sparklineSegments(samples, selector);
  if (!segments.length) return <div className="spark-empty">等待遥测样本</div>;
  return (
    <svg className="sparkline" viewBox="0 0 100 100" preserveAspectRatio="none" aria-label="历史趋势">
      {segments.map((segment, index) => <polyline key={index} points={segment.join(" ")} fill="none" stroke={color} strokeWidth="3" vectorEffect="non-scaling-stroke" />)}
    </svg>
  );
}
