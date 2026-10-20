import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
vi.mock("./api", () => ({ api: vi.fn(), currentIdentityEpoch: () => 0 }));
import { MachinePolicyEditor, previewCpuBudget } from "./MachineSettings";

describe("shared machine budget", () => {
  it.each([[384, 25, 288], [192, 25, 144], [7, 25, 5], [1, 25, 0], [384, 50, 192], [384, 100, 0]])(
    "%i threads with %i percent reserved previews %i", (total, reserve, expected) => {
      expect(previewCpuBudget({ total_cpus: total }, { max_cpus: 10000, shared_machine: true, cpu_reserve_percent: reserve })).toBe(expected);
    },
  );
  it("does not silently reclassify legacy machines and respects the invitation ceiling", () => {
    expect(previewCpuBudget({ total_cpus: 16 }, { max_cpus: 16 })).toBe(16);
    expect(previewCpuBudget({ total_cpus: 16 }, { max_cpus: 16, shared_machine: true, member_execution_limit: { max_cpus: 2 } })).toBe(2);
  });
  it("renders owner controls and pending audit without pretending an OS quota or acceptance pass", () => {
    const html = renderToStaticMarkup(<MachinePolicyEditor
      machine={{ machine_id: "shared", total_cpus: 384, total_memory_mb: 262144, total_gpus: 0 }}
      policy={{ owner_mode: "open", max_cpus: 384, shared_machine: true, cpu_reserve_percent: 25 }}
      config={{ enabled: true, execution_provenance: { admission_policy: "trust_first", member_audit_state: "pending" } }}
      canEdit={true} />);
    expect(html).toContain("288 / 384");
    expect(html).toContain("CPU 预留百分比");
    expect(html).toContain('min="25"');
    expect(html).toContain("异步待验收");
    expect(html).toContain("不是操作系统 CPU 时间配额");
  });
  it.each([["queued", "异步排队中"], ["passed", "已通过"], ["failed", "失败，停止新派发"]])(
    "shows scientific %s separately from lifecycle acceptance", (state, label) => {
      const html = renderToStaticMarkup(<MachinePolicyEditor
        machine={{ machine_id: "member", total_cpus: 16, total_memory_mb: 32768 }}
        policy={{ owner_mode: "open", max_cpus: 12, shared_machine: true }}
        config={{ enabled: state !== "failed", execution_provenance: {
          admission_policy: "trust_first", member_audit_state: "pending", scientific_audit_state: state,
        } }} canEdit={false} />);
      expect(html).toContain(label);
      expect(html).toContain("重启、取消和断线等完整运行验收单独记录");
    },
  );
});
