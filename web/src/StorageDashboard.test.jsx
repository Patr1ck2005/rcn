import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import StorageDashboard from "./StorageDashboard";
import { storageBytes, storageDashboardModel, volumeForecast, nextStorageExpiry } from "./storageDashboardModel";

const GiB = 1024 ** 3;
const inventory = (overrides = {}) => ({
  generated_at: "2026-10-23T06:00:00Z", backfill_complete: true,
  coverage: "registered manifests only", unattributed_device_bytes: null,
  volumes: [{ host_id: "center", volume_id: "F:", physical_device_id: "disk-2", total_bytes: 100 * GiB,
    free_bytes: 20 * GiB, reserved_bytes: 3 * GiB, hard_reserve_bytes: 10 * GiB, usable_bytes: 7 * GiB,
    sampled_at: "2026-10-23T06:00:00Z", sample_count: 8, growth_bytes_per_day: GiB, days_to_reserve: 7 }],
  projects: [{ project_id: "project-a", role: "origin_spool", location: "center", bytes: 5 * GiB,
    pending_custody_bytes: 0, eligible_bytes: 2 * GiB, confirmed_retired_bytes: GiB }], ...overrides,
});

describe("storage dashboard evidence", () => {
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-23T06:00:00Z")); });
  afterEach(() => vi.useRealTimers());
  it("expires cached estimates without a new server response and schedules only the next expiry", () => {
    const data = inventory();
    expect(volumeForecast(data.volumes[0], true).known).toBe(true);
    expect(nextStorageExpiry(data)).toBe(Date.now() + 120001);
    vi.setSystemTime(new Date("2026-10-23T06:02:01Z"));
    expect(storageDashboardModel({}, data).volumes[0].forecast).toMatchObject({ known: false, reason: "容量采样已过期" });
    expect(nextStorageExpiry(data)).toBeNull();
  });
  it("keeps zero, missing and invalid byte evidence distinct", () => {
    expect(storageBytes(0)).toBe("0 B");
    for (const value of [null, undefined, -1, NaN, Infinity, "1024"]) expect(storageBytes(value)).toBe("未知");
    expect(storageBytes(GiB)).toBe("1 GiB");
  });

  it("deduplicates two roles on one physical volume without summing logical bytes", () => {
    const data = inventory(); data.volumes.push({ ...data.volumes[0], host_id: "CENTER", volume_id: "f:" });
    const model = storageDashboardModel({ lifecycle: { pending_retirements: 99 } }, data);
    expect(model.volumes).toHaveLength(1);
    expect(model.volumes[0].free_bytes).toBe(20 * GiB);
    expect(model.projects[0]).toMatchObject({ logical: 5 * GiB, pending: 0, eligible: 2 * GiB, retired: GiB });
    expect(model.unknownPhysicalBytes).toBeNull();
  });

  it("does not translate lifecycle counts or absent categories into byte totals", () => {
    const model = storageDashboardModel({ lifecycle: { pending_retirements: 99 } }, inventory({ projects: [{ bytes: 0 }] }));
    expect(model.projects[0]).toMatchObject({ logical: 0, pending: null, eligible: null, retired: null });
  });

  it("uses measured physical occupancy for the 80 and 90 percent alerts", () => {
    const first = inventory().volumes[0];
    const model = storageDashboardModel({}, inventory({ volumes: [first, { ...first, volume_id: "E:", free_bytes: 10 * GiB }] }));
    expect(model.volumes.map((row) => row.alert)).toEqual(["warning", "critical"]);
    expect(storageDashboardModel({}, inventory({ volumes: [{ ...first, free_bytes: null }] })).volumes[0].usedPercent).toBeNull();
  });

  it("keeps allocated-file evidence separate and withholds stale occupancy", () => {
    const model = storageDashboardModel({}, inventory({ projects: [
      { bytes: GiB, physical_bytes: GiB / 2, registered_files: 2, measured_files: 2, occupancy_oldest_observed_at: "2026-10-23T06:00:00Z" },
      { bytes: GiB, physical_bytes: GiB / 2, occupancy_stale: true },
    ] }));
    expect(model.projects[0]).toMatchObject({ logical: GiB, physical: GiB / 2 });
    expect(model.projects[1].physical).toBeNull();
  });

  it.each([
    [{ forecast_reason: "no_confirmed_natural_growth" }, true], [{ sample_count: 2 }, true], [{ stale: true }, true], [{ growth_bytes_per_day: 0 }, true],
    [{ growth_bytes_per_day: -GiB }, true], [{ days_to_reserve: null }, true], [{}, false],
  ])("withholds a fill estimate when evidence is insufficient or growth is nonpositive (%o)", (changes, complete) => {
    expect(volumeForecast({ ...inventory().volumes[0], ...changes }, complete).known).toBe(false);
  });

  it("renders physical, logical, coverage and safe archive continuation evidence", () => {
    const markup = renderToStaticMarkup(<StorageDashboard status={{ operation_continuations: [{ operation_id: "restore-original", state: "deferred", next_action: "核对原回执" }] }} inventory={inventory()} />);
    expect(markup).toContain("活跃容量承诺"); expect(markup).toContain("7 GiB");
    expect(markup).toContain("80% 软告警"); expect(markup).toContain("7 天后达到保留线");
    expect(markup).toContain("硬链接"); expect(markup).toContain("未知"); expect(markup).toContain("restore-original");
    expect(markup).toContain("本地客户端或来源项目 Agent"); expect(markup).not.toContain("<button");
  });
});
