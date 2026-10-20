import { describe, expect, it, vi } from "vitest";
import { markTokenIssuance, pendingTokenIssuance, tokenRequestId } from "./tokenIssuance";
const storage = () => {
  const values = new Map();
  return { getItem: (key) => values.get(key) || null, setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key) };
};
describe("token issuance checkpoints", () => {
  it("uses secure random values when randomUUID is unavailable in HTTP context", () => {
    const getRandomValues = crypto.getRandomValues.bind(crypto);
    vi.stubGlobal("crypto", { getRandomValues });
    try {
      const first = tokenRequestId(), second = tokenRequestId();
      expect(first).toMatch(/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
      expect(second).not.toBe(first);
    } finally { vi.unstubAllGlobals(); }
  });
  it("persists only a non-secret user identity and timestamp across a reload", () => {
    const memory = storage();
    markTokenIssuance(memory, "admin-a", "member-a", true);
    expect(pendingTokenIssuance(memory, "admin-a")["member-a"]).toMatchObject({ user_id: "member-a", started_at: expect.any(String) });
    expect(Object.keys(pendingTokenIssuance(memory, "admin-a")["member-a"])).toEqual(["user_id", "started_at", "request_id"]);
    expect(pendingTokenIssuance(memory, "admin-a")["member-a"].request_id).toMatch(/^[a-f0-9-]{36}$/);
    expect(pendingTokenIssuance(memory, "admin-b")).toEqual({});
  });
  it("clears only an explicitly completed issuance", () => {
    const memory = storage();
    markTokenIssuance(memory, "admin", "member", true);
    markTokenIssuance(memory, "admin", "member", false);
    expect(pendingTokenIssuance(memory, "admin")).toEqual({});
  });
  it("preserves an Agent issuance scope in the same per-user checkpoint without credentials", () => {
    const memory = storage();
    markTokenIssuance(memory, "admin", "member", true, true);
    const original = pendingTokenIssuance(memory, "admin").member;
    expect(original.agent).toBe(true);
    expect(original).not.toHaveProperty("token");
    expect(pendingTokenIssuance(memory, "admin").member.request_id).toBe(original.request_id);
    markTokenIssuance(memory, "admin", "different-member", true);
    expect(pendingTokenIssuance(memory, "admin")["different-member"]).not.toHaveProperty("agent");
    markTokenIssuance(memory, "admin", "member", false);
    expect(pendingTokenIssuance(memory, "admin").member).toBeUndefined();
  });
  it("fails closed when the checkpoint cannot be read", () => {
    expect(() => pendingTokenIssuance({ getItem: () => "[]" }, "admin")).toThrow("检查点");
  });
});
