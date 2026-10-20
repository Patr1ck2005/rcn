import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { PersonalAccessSummary, submissionPolicyDraft } from "./PersonalAccess";

describe("person submission and credit presentation", () => {
  it("creates an explicitly unapproved personal draft and binds the selected person", () => {
    expect(submissionPolicyDraft("member-a", null)).toMatchObject({ person_id: "member-a", approved: false, quota_mode: "shadow", auto_project: true });
    expect(submissionPolicyDraft("member-b", { person_id: "member-a", approved: true }).person_id).toBe("member-b");
  });
  it("shows the policy mode, real balance, reservations and the two compute pools", () => {
    const html = renderToStaticMarkup(<PersonalAccessSummary access={{ policy: { approved: true, paused: false, allowed_profiles: ["fixed-profile"], quota_mode: "shadow" }, usage: {} }} credits={{ available_cpu_core_hours: 12.5, available_gpu_device_hours: 2, reserved_cpu_core_hours: 3, reserved_gpu_device_hours: 1, settings: { metering_enabled: false } }} />);
    for (const text of ["已开通", "影子记账", "12.5", "互助池", "免费空闲池", "已预留", "不因余额阻止派发"]) expect(html).toContain(text);
  });
  it("keeps simulated usage separate from redeemable balances", () => {
    const html = renderToStaticMarkup(<PersonalAccessSummary credits={{ available_cpu_core_hours: 0,
      available_gpu_device_hours: 0, reserved_cpu_core_hours: 0, reserved_gpu_device_hours: 0,
      settings: { metering_enabled: true }, shadow_balance: { cpu_core_hours: 12.5,
        gpu_device_hours: 2, reserved_cpu_core_hours: 3, reserved_gpu_device_hours: 1 } }} />);
    expect(html).toContain("影子记录（不能兑换）：CPU 12.5");
    expect(html).toContain("开启计量不会自动转为上方的正式额度");
    expect(html).toContain("<dt>可用 CPU 核时</dt><dd>0</dd>");
  });
  it("does not mix ambiguous legacy balances into the real or shadow balance", () => {
    const html = renderToStaticMarkup(<PersonalAccessSummary credits={{ available_cpu_core_hours: 0,
      shadow_balance: { cpu_core_hours: 3 }, legacy_balance: { cpu_core_hours: 12.5 },
      legacy_isolation: { present: true } }} />);
    expect(html).toContain("影子记录（不能兑换）：CPU 3");
    expect(html).toContain("旧账记录（不能兑换）：CPU 12.5");
    expect(html).toContain("需要管理员核对，不会自动计入正式额度");
    expect(html).toContain("<dt>可用 CPU 核时</dt><dd>0</dd>");
  });
});
