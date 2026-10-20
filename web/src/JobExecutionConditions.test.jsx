import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { JobExecutionConditionsSnapshot } from "./JobExecutionConditions";

describe("manually checked Job execution conditions", () => {
  it("renders actual environment, project concurrency and original check time", () => {
    const html = renderToStaticMarkup(<JobExecutionConditionsSnapshot data={{ generated_at: "2026-10-17T12:00:00Z", execution_environment: { status: "executable", capacity_hint: { eligible_slots: 2 } }, project_concurrency: { active_units: 1, prepared_units: 0, max_running_units: 4 } }} />);
    expect(html).toContain("环境就绪 · 2 可用 slot");
    expect(html).toContain("1 运行 + 0 预备 / 4 上限");
    expect(html).toContain('dateTime="2026-10-17T12:00:00Z"');
  });
  it("preserves unknown values without manufacturing zero capacity or readiness", () => {
    const html = renderToStaticMarkup(<JobExecutionConditionsSnapshot data={{ generated_at: null, execution_environment: null, project_concurrency: null }} />);
    expect(html).toContain("环境状态未知");
    expect(html).toContain("未知 运行 + 未知 预备 / 未知 上限");
    expect(html).toContain("检查时间未知");
    expect(html).not.toContain("环境就绪"); expect(html).not.toContain("0 运行");
  });
});
