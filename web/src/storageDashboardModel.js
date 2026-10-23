const number = (value) => typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
const array = (value) => Array.isArray(value) ? value : [];

export function storageBytes(value) {
  if (number(value) === null) return "未知";
  if (value === 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${(value / 1024 ** index).toLocaleString("zh-CN", { maximumFractionDigits: index ? 1 : 0 })} ${units[index]}`;
}

export function storageTime(value) {
  if (!value || !Number.isFinite(new Date(value).getTime())) return "未知";
  return new Date(value).toLocaleString("zh-CN", { hour12: false });
}

const volumeLifetime = 120000;
const occupancyLifetime = 86400000;
const expired = (value, lifetime, now) => !value || !Number.isFinite(Date.parse(value)) || now - Date.parse(value) > lifetime;

export function nextStorageExpiry(inventory = {}, now = Date.now()) {
  const deadlines = [
    ...array(inventory.volumes).filter((row) => !row.stale).map((row) => Date.parse(row.sampled_at) + volumeLifetime + 1),
    ...array(inventory.projects).filter((row) => !row.occupancy_stale).map((row) => Date.parse(row.occupancy_oldest_observed_at) + occupancyLifetime + 1),
  ].filter((value) => Number.isFinite(value) && value > now);
  return deadlines.length ? Math.min(...deadlines) : null;
}

export function volumeForecast(volume, complete, now = Date.now()) {
  const growth = number(volume.growth_bytes_per_day);
  const days = number(volume.days_to_reserve);
  if (volume.stale || expired(volume.sampled_at, volumeLifetime, now)) return { known: false, reason: "容量采样已过期" };
  if (volume.forecast_reason === "no_confirmed_natural_growth") return { known: false, reason: "尚无正常文件增长样本，迁移与回填不计入" };
  if (volume.forecast_reason === "nonpositive_growth" || (typeof volume.growth_bytes_per_day === "number" && volume.growth_bytes_per_day <= 0)) {
    return { known: false, reason: "没有正净增长，无法估计耗尽时间" };
  }
  if (!complete || growth === null || !growth || days === null || number(volume.sample_count) === null || volume.sample_count < 3) {
    return { known: false, reason: "固定时间桶样本或登记覆盖不足" };
  }
  return { known: true, growth, days };
}

// Snapshot fields are nullable evidence. Never turn absent accounting into zero,
// derive physical bytes from manifests, or add capacity reported by two roots.
export function storageDashboardModel(status = {}, inventory = status.inventory || {}, now = Date.now()) {
  const seen = new Set();
  const volumes = array(inventory.volumes).filter((volume) => {
    if (!volume.host_id || !volume.volume_id) return true;
    const key = `${volume.host_id.toLowerCase()}\0${volume.volume_id.toLowerCase()}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).map((volume) => {
    const total = number(volume.total_bytes);
    const free = number(volume.free_bytes);
    const usedPercent = total && free !== null && free <= total ? (total - free) / total * 100 : null;
    return {
      ...volume, total_bytes: total, free_bytes: free,
      reserved_bytes: number(volume.reserved_bytes), usable_bytes: number(volume.usable_bytes),
      hard_reserve_bytes: number(volume.hard_reserve_bytes), usedPercent,
      alert: usedPercent >= 90 ? "critical" : usedPercent >= 80 ? "warning" : "",
      stale: volume.stale || expired(volume.sampled_at, volumeLifetime, now),
      forecast: volumeForecast(volume, inventory.backfill_complete === true, now),
    };
  });
  return {
    generatedAt: inventory.generated_at || status.generated_at,
    complete: inventory.backfill_complete === true,
    coverage: typeof inventory.coverage === "string" ? inventory.coverage : "登记清单与托管回执的覆盖范围尚未提供",
    unknownPhysicalBytes: number(inventory.unattributed_device_bytes),
    roots: Object.entries(status.roles || {}).map(([role, root]) => ({ role, ...root })),
    volumes,
    projects: array(inventory.projects).map((row) => ({ ...row,
      logical: number(row.logical_registered_bytes ?? row.registered_bytes ?? row.bytes),
      physical: row.occupancy_stale === true || expired(row.occupancy_oldest_observed_at, occupancyLifetime, now) ? null : number(row.physical_bytes),
      occupancy_stale: row.occupancy_stale === true || expired(row.occupancy_oldest_observed_at, occupancyLifetime, now),
      pending: number(row.pending_custody_bytes), eligible: number(row.eligible_bytes),
      retired: number(row.confirmed_retired_bytes),
    })),
    growth: array(inventory.growth_24h),
    continuations: array(status.operation_continuations || inventory.operation_continuations),
  };
}
