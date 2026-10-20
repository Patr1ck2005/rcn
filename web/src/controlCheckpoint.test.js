import { describe, expect, it } from "vitest";
import { controlCheckpoint, controlCheckpointKey, controlResumeBody, controlScope, loadControlCheckpoint, saveControlCheckpoint, validateControlScope } from "./controlCheckpoint";
const scope = controlScope("machine", "emergency_stop_host", ["machine-a"]);
const ticket = { action: scope.action, ticket_id: "ticket", confirmation_hash: "hash", issued_by: "actor", targets: [{ machine_id: "machine-a" }], requires_break_glass: true };
const storage = () => { const values = new Map(); return { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) }; };
describe("shared control durable checkpoints", () => {
  it("never persists the PIN and requires a fresh explicit PIN for resumption", () => {
    const local = storage(), value = controlCheckpoint("actor", scope, { ...ticket, break_glass_pin: "secret-pin" }, { ticket_id: "ticket", confirmation_hash: "hash", typed_machine_id: "machine-a", process_set_hash: "processes", break_glass_pin: "secret-pin" });
    saveControlCheckpoint(local, value);
    expect(local.getItem(controlCheckpointKey("actor", scope))).not.toContain("secret-pin");
    const restored = loadControlCheckpoint(local, "actor", scope);
    expect(() => controlResumeBody(restored, {})).toThrow("重新输入");
    expect(controlResumeBody(restored, { break_glass_pin: "fresh-pin", typed_machine_id: "machine-a" })).toEqual({ ...value.body, break_glass_pin: "fresh-pin" });
    expect(restored.body).not.toHaveProperty("break_glass_pin");
  });
  it("isolates actor, action and exact target set and rejects mismatched receipts", () => {
    const local = storage(), value = controlCheckpoint("actor", scope, ticket, { ticket_id: "ticket", confirmation_hash: "hash" });
    saveControlCheckpoint(local, value);
    expect(loadControlCheckpoint(local, "other", scope)).toBeNull();
    expect(loadControlCheckpoint(local, "actor", controlScope("machine", scope.action, ["other"]))).toBeNull();
    expect(() => controlCheckpoint("other", scope, ticket, value.body)).toThrow("不匹配");
    expect(() => validateControlScope({ ticket_id: "ticket", operation_id: "run", requested_by: "other", targets: [{ machine_id: "machine-a" }] }, value)).toThrow("不匹配");
    expect(() => validateControlScope({ ticket_id: "ticket", operation_id: "run", requested_by: "actor", targets: [{ machine_id: "other" }] }, value)).toThrow("不匹配");
  });
});
