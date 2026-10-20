import { describe, expect, it } from "vitest";
import { countsTotal, durationText, intervalText, forecastText, numberText, percentText, projectRows, insightScopeLabels } from "./insightFormat";
describe("insights preserve unknown and forecast boundaries", () => {
  it("labels a project-filtered member view as visible work rather than the whole network", () => {
    expect(insightScopeLabels({ scope: { jobs: "cluster", projects_filtered: true } })).toMatchObject({
      title: "可见任务总览", projects: "全部可见项目", tasks: "可见任务", filtered: true });
    expect(insightScopeLabels({ scope: { jobs: "own", projects_filtered: true } }).title).toBe("我的任务总览");
    expect(insightScopeLabels({ scope: { jobs: "cluster", projects_filtered: false } }).title).toBe("全网运行总览");
  });
  it("does not turn missing values into zero", () => {
    expect(numberText(null)).toBe("—"); expect(percentText(null)).toBe("—");
    expect(numberText(NaN)).toBe("—"); expect(percentText(Infinity)).toBe("—"); expect(numberText(false)).toBe("—"); expect(durationText(null)).toBe("待估计");
    expect(durationText(0)).toBe("无待算工作"); expect(durationText(60)).toBe("1 分钟");
  });
  it("shows stale or blocked estimates without a false countdown", () => {
    expect(forecastText({ seconds: 400 }, true).value).toBe("待刷新");
    expect(forecastText({ seconds: null, basis: "blocked_work" }).detail).toContain("受阻");
    expect(forecastText({ seconds: 3600, basis: "current_slots_declared" }).value).toBe("1 小时");
  });
  it("filters project identities without interpreting user input", () => {
    const data = { projects: [{project_id: "Laser-A"}, {project_id: "Acoustic-B"}] };
    expect(projectRows(data, "laser").map(p => p.project_id)).toEqual(["Laser-A"]);
    expect(projectRows(data, "<script>")).toEqual([]); expect(projectRows(null)).toEqual([]);
  });
  it("counts each operational category once", () => {
    expect(countsTotal({completed:7,running:2,waiting:3,collecting:1,attention:1,cancelled:1,ignored:900})).toBe(15);
    expect(countsTotal()).toBe(0);
    expect(intervalText(150)).toBe("2 分 30 秒");
    expect(intervalText(3600)).toBe("1 小时");
  });
});
