import { describe, expect, it, vi } from "vitest";
import { contributionScope, contributionKey, loadContributionCheckpoints, saveContributionCheckpoints,
  safeContributionCheckpoint, validateContributionReceipt, submitContribution, readContributionOriginal } from "./memberContributionCheckpoint";

const scope = { actor_id: "alice", center_url: "https://center.example", contribution_id: "11111111-2222-4333-8444-555555555555" };
const checkpoint = { ...scope, operation_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", kind: "setup", action: "setup", machine_id: "MEMBER-ALICE", expected_revision: 0 };
const receipt = (status = "completed") => ({ operation: { ...checkpoint, payload_sha256: "a".repeat(64), status },
  result: status === "completed" ? { contribution_id: scope.contribution_id, revision: 1, machine_id: "MEMBER-ALICE", configured: true } : null });
const storage = () => {
  const values = new Map();
  return { values, getItem: (key) => values.get(key) || null, setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key) };
};

describe("member contribution original-request checkpoints", () => {
  it("persists only the exact nonsecret allowlist and reloads the original ID", () => {
    const store = storage();
    saveContributionCheckpoints(store, scope, [{ ...checkpoint, invite: "private-invitation-code", token: "private-token", payload: { max_memory_mb: 2048 }, body: { accepted: true } }]);
    expect([...store.values.values()].join("")).not.toMatch(/private|invite|token|payload|body|max_memory/);
    expect(loadContributionCheckpoints(store, scope)).toEqual([checkpoint]);
    saveContributionCheckpoints(store, scope, []);
    expect(store.getItem(contributionKey(scope))).toBeNull();
  });

  it.each(["actor_id", "center_url", "contribution_id"])("isolates the %s scope including the same person at a new center", (field) => {
    const store = storage();
    saveContributionCheckpoints(store, scope, [checkpoint]);
    const other = { ...scope, [field]: field === "contribution_id" ? "22222222-2222-4333-8444-555555555555" : "other" };
    expect(() => safeContributionCheckpoint(other, checkpoint)).toThrow("不匹配");
    if (field === "contribution_id") expect(() => loadContributionCheckpoints(store, other)).toThrow("不匹配");
    else expect(loadContributionCheckpoints(store, other)).toEqual([]);
    expect(loadContributionCheckpoints(store, scope)).toEqual([checkpoint]);
  });

  it("derives scope from the live session and original local installation", () => {
    expect(contributionScope({ actor: { actor_id: "alice" }, center_url: "https://center.example/" }, { contribution_id: scope.contribution_id })).toEqual(scope);
    expect(() => contributionScope({ actor: { actor_id: "alice" } }, {})).toThrow();
    expect(() => safeContributionCheckpoint(scope, { ...checkpoint, kind: "setup", action: "pause" })).toThrow();
  });

  it.each(["operation_id", "actor_id", "center_url", "kind", "machine_id", "expected_revision"])("rejects an original receipt with changed %s", (field) => {
    const value = receipt(); value.operation[field] = field === "expected_revision" ? 7 : "other";
    expect(() => validateContributionReceipt(value, checkpoint)).toThrow("不匹配");
  });

  it.each(["contribution_id", "machine_id", "revision"])("rejects changed result %s proof", (field) => {
    const value = receipt(); value.result[field] = field === "revision" ? -1 : "other";
    expect(() => validateContributionReceipt(value, checkpoint)).toThrow("范围证明");
  });

  it("recovers a lost reply using one POST and the same original GET", async () => {
    const request = vi.fn().mockRejectedValueOnce(new Error("reply lost")).mockResolvedValueOnce(receipt());
    await expect(submitContribution(request, checkpoint, { invite: "secret", accepted: true })).resolves.toEqual(receipt());
    expect(request.mock.calls.map(([path, options]) => [path, options?.method || "GET"])).toEqual([
      ["/local/v1/contribution/setup", "POST"], [`/local/v1/contribution/operations/${checkpoint.operation_id}`, "GET"],
    ]);
    expect(JSON.parse(request.mock.calls[0][1].body)).toEqual({ invite: "secret", accepted: true, operation_id: checkpoint.operation_id, expected_revision: 0 });
  });

  it("returns unknown without converting the original query into another write", async () => {
    const request = vi.fn().mockRejectedValueOnce(new Error("reply lost")).mockResolvedValue(receipt("unknown"));
    await expect(submitContribution(request, checkpoint, { invite: "secret" })).resolves.toEqual(receipt("unknown"));
    await expect(readContributionOriginal(request, checkpoint)).resolves.toEqual(receipt("unknown"));
    expect(request.mock.calls.filter(([, options]) => options?.method === "POST")).toHaveLength(1);
  });

  it("retains a safe local pause result while its child center receipt is unknown", () => {
    const value = receipt("unknown");
    value.result = { contribution_id: scope.contribution_id, machine_id: "MEMBER-ALICE", revision: 2, paused: true, policy_sync_pending: true };
    expect(validateContributionReceipt(value, checkpoint)).toEqual(value);
    value.result.contribution_id = "other";
    expect(() => validateContributionReceipt(value, checkpoint)).toThrow("范围证明");
  });

  it("accepts a terminal conflict only with an exact local result and safe failure reason", () => {
    const value = receipt(); value.operation.status = "failed";
    expect(() => validateContributionReceipt(value, checkpoint)).toThrow("失败回执");
    value.operation.error = { reason_code: "machine_policy_revision_conflict", message: "original rejected" };
    expect(validateContributionReceipt(value, checkpoint)).toEqual(value);
  });

  it("marks only an authoritative original 404 as not delivered and never retries", async () => {
    const failure = Object.assign(new Error("state conflict"), { status: 409 });
    const request = vi.fn().mockRejectedValueOnce(failure).mockRejectedValueOnce(Object.assign(new Error("absent"), { status: 404, reasonCode: "contribution_operation_not_found" }));
    await expect(submitContribution(request, checkpoint, {})).rejects.toMatchObject({ notDelivered: true });
    expect(request).toHaveBeenCalledTimes(2);
  });

  it("does not treat a masked authorization or machine 404 as proof of non-delivery", async () => {
    const request = vi.fn().mockRejectedValueOnce(new Error("reply lost"))
      .mockRejectedValueOnce(Object.assign(new Error("machine unavailable"), { status: 404, reasonCode: "machine_not_found" }));
    await expect(submitContribution(request, checkpoint, {})).rejects.toMatchObject({ notDelivered: false });
  });

  it("bounds persisted pending requests while permitting one extra safety pause", () => {
    const store = storage();
    const pause = { ...checkpoint, operation_id: "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee", kind: "preferences", action: "pause" };
    expect(saveContributionCheckpoints(store, scope, [checkpoint, pause])).toEqual([checkpoint, pause]);
    expect(() => saveContributionCheckpoints(store, scope, [checkpoint, pause, pause])).toThrow("原接入请求");
  });
});
