import { describe, expect, it } from "vitest";
import { policyEditorState, reconcilePolicyEditor } from "./MachineSettings";

const policy = (owner_mode = "open") => ({ machine_id: "M", owner_mode, max_cpus: 8, max_memory_mb: 4096, max_gpus: 0, max_concurrent_units: 2 });

describe("machine policy editor revision binding", () => {
  it("refreshes an unchanged editor and carries the matching revision", () => {
    const before = policyEditorState("M", policy(), "a".repeat(64));
    const next = reconcilePolicyEditor(before, "M", policy("paused"), "b".repeat(64));
    expect(next.draft.owner_mode).toBe("paused");
    expect(next.revisionHash).toBe("b".repeat(64));
  });
  it("keeps a dirty draft bound to its original policy despite a newer pause", () => {
    const before = policyEditorState("M", policy(), "a".repeat(64));
    before.draft.values.max_cpus = 4;
    const next = reconcilePolicyEditor(before, "M", policy("paused"), "b".repeat(64));
    expect(next).toBe(before);
    expect(next.policy.owner_mode).toBe("open");
    expect(next.revisionHash).toBe("a".repeat(64));
    expect(next.draft.values.max_cpus).toBe(4);
  });
  it("discards another machine's dirty baseline", () => {
    const before = policyEditorState("M", policy(), "a".repeat(64));
    before.draft.values.max_cpus = 4;
    const next = reconcilePolicyEditor(before, "N", { ...policy("paused"), machine_id: "N" }, "b".repeat(64));
    expect(next.machineId).toBe("N");
    expect(next.draft.owner_mode).toBe("paused");
    expect(next.revisionHash).toBe("b".repeat(64));
  });
});
