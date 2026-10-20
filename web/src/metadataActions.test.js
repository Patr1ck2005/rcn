import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, configureMemberClient, setToken } from "./api";
import { beginMetadataAction, finishMetadataAction, metadataActionKey, metadataActionSending, metadataActionSpec, pendingMetadataAction, releaseMetadataSender, setMetadataActor, subscribeMetadataActions, validateMetadataReceipt } from "./metadataActions";

let storage;
const spec = () => metadataActionSpec("/v1/users/alice", "PUT", '{}');
const write = (body = { user_id: "alice", active: false }) => api("/v1/users/alice", { method: "PUT", body: JSON.stringify(body) });
const json = (value, status = 200) => new Response(JSON.stringify(value), { status });
beforeEach(() => {
  const values = new Map();
  storage = { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key) };
  vi.stubGlobal("sessionStorage", storage); configureMemberClient(false); setMetadataActor("admin-one");
});
afterEach(() => { setMetadataActor(null); configureMemberClient(false); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("metadata route boundary", () => {
  it.each([
    ["PUT", "/v1/users/alice", "user_update", "alice"],
    ["DELETE", "/v1/users/alice/tokens/secret-id", "user_token_revoke", "alice"],
    ["PUT", "/v1/projects/p", "project_update", "p"],
    ["POST", "/v1/admin/project-registrations/r/review", "project_registration_review", "r"],
    ["PUT", "/v1/projects/p/trusted-users/alice", "project_trusted_user_add", "p"],
    ["DELETE", "/v1/projects/p/trusted-users/alice", "project_trusted_user_remove", "p"],
    ["POST", "/v1/admin/projects/p/freeze", "project_freeze", "p"],
    ["PUT", "/v1/admin/people/alice/submission-policy", "personal_submission_policy", "alice"],
    ["PUT", "/v1/machines/M/policy", "machine_policy", "M"],
    ["PUT", "/v1/machines/M/execution-tuning", "machine_execution_tuning", "M"],
    ["PUT", "/v1/machines/M/external-comsol-consent", "machine_external_comsol_consent", "M"],
    ["POST", "/v1/admin/resource-policies/profile/confirm", "resource_policy_confirm", "profile"],
    ["DELETE", "/v1/solver-approvals/a", "solver_approval_revoke", "a"],
    ["POST", "/v1/admin/member-admissions/a/revoke", "member_admission_revoke", "a"],
    ["POST", "/v1/admin/onboarding/M/preflight", "onboarding_preflight", "M"],
    ["POST", "/v1/admin/jobs/job/units/unit/abandon-and-retry", "abandon_attempt", "job"],
    ["PUT", "/v1/settings/features", "feature_settings", "global"],
    ["PUT", "/v1/admin/break-glass/pin", "break_glass_pin", "global"],
    ["POST", "/v1/admin/scheduling/confirm", "scheduling_confirm", "global"],
  ])("binds %s %s", (method, path, kind, subject_id) => {
    expect(metadataActionSpec(path, method, '{}')).toMatchObject({ kind, subject_id });
    expect(metadataActionSpec(path, "GET", '{}')).toBeNull();
  });
  it("uses explicit creation identity and excludes existing operation and local protocols", () => {
    expect(metadataActionSpec("/v1/profiles", "POST", '{"profile_id":"p"}')).toMatchObject({ kind: "profile_create", subject_id: "p" });
    expect(metadataActionSpec("/v1/project-registrations", "POST", '{"project_id":"p"}')).toMatchObject({ kind: "project_registration", subject_id: "p" });
    for (const path of ["/local/v1/contribution/setup", "/local/v1/contribution/preferences", "/v1/users/alice/tokens", "/v1/solver-approvals", "/v1/admin/control/confirm", "/v1/member/submissions/o/confirm"]) expect(metadataActionSpec(path, "POST", '{}')).toBeNull();
  });
});

describe("durable metadata identity", () => {
  it("persists no payload, PIN or credential and blocks a second same-frame intent", async () => {
    let resolve;
    vi.stubGlobal("fetch", vi.fn(() => new Promise((done) => { resolve = done; })));
    const first = api("/v1/admin/break-glass/pin", { method: "PUT", body: '{"pin":"PIN-MUST-NOT-PERSIST"}' });
    const pending = pendingMetadataAction("admin-one");
    expect(pending.kind).toBe("break_glass_pin");
    expect(JSON.stringify(pending)).not.toContain("PIN-MUST-NOT-PERSIST");
    expect(Object.keys(pending).sort()).toEqual(["actor_id", "created_at", "kind", "label", "method", "path", "request_id", "schema_version", "subject_id"]);
    expect(metadataActionSending(pending.request_id)).toBe(true);
    await expect(write()).rejects.toThrow("先核对原操作");
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][1].headers.get("X-RCN-Request-ID")).toBe(pending.request_id);
    resolve(json({ configured: true })); await first;
    expect(pendingMetadataAction("admin-one")).toBeNull();
    expect(metadataActionSending(pending.request_id)).toBe(false);
  });
  it("a lost reply retains the original UUID across reload and only allows receipt reads", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("reply lost"); }));
    await expect(write()).rejects.toThrow("reply lost");
    const original = pendingMetadataAction("admin-one");
    setMetadataActor(null); setMetadataActor("admin-one");
    await expect(write({ active: true })).rejects.toThrow("先核对原操作");
    expect(fetch).toHaveBeenCalledTimes(1);
    const receipt = { request_id: original.request_id, kind: original.kind, subject_id: original.subject_id, state: "completed", result: { user_id: "alice", active: false } };
    fetch.mockResolvedValueOnce(json(receipt));
    const found = await api(`/v1/metadata-operations/${original.request_id}`);
    expect(validateMetadataReceipt(found, original)).toEqual({ user_id: "alice", active: false });
    expect(fetch.mock.calls.at(-1)[1].method).toBeUndefined();
    finishMetadataAction(original, storage, found.result);
    fetch.mockResolvedValueOnce(json({ user_id: "alice", active: true })); await write({ active: true });
    expect(fetch.mock.calls.at(-1)[1].headers.get("X-RCN-Request-ID")).not.toBe(original.request_id);
  });
  it.each([202, 500])("retains pending for ambiguous or accepted HTTP %s", async (status) => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ state: "pending" }, status)));
    await expect(write()).rejects.toThrow();
    expect(pendingMetadataAction("admin-one").request_id).toBeTruthy();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("treats an explicit rejected transaction as rejected and allows a new draft", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json({ detail: "revision conflict" }, 409)));
    await expect(write()).rejects.toThrow("revision conflict");
    expect(pendingMetadataAction("admin-one")).toBeNull();
    fetch.mockResolvedValueOnce(json({ user_id: "alice", active: true })); await write();
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it("keeps a successful but undecodable response pending", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("truncated", { status: 200 })));
    await expect(write()).rejects.toThrow();
    expect(pendingMetadataAction("admin-one")).toMatchObject({ kind: "user_update" });
  });
  it("rejects an obsolete identity after a completed write without delivering its result", async () => {
    let resolve;
    vi.stubGlobal("fetch", vi.fn(() => new Promise((done) => { resolve = done; })));
    const result = write(); setToken("another-person-token");
    resolve(json({ user_id: "alice", roles: ["admin"] }));
    await expect(result).rejects.toMatchObject({ name: "AbortError" });
    expect(pendingMetadataAction("admin-one")).toBeNull();
  });
  it("does not broadcast an old epoch's result after returning to the same actor", async () => {
    let resolve; const events = [];
    const unsubscribe = subscribeMetadataActions((event) => { if (event?.type === "completed") events.push(event); });
    vi.stubGlobal("fetch", vi.fn(() => new Promise((done) => { resolve = done; })));
    try {
      const result = write(); setToken("identity-B"); setMetadataActor("admin-two");
      setToken("identity-A-new"); setMetadataActor("admin-one");
      resolve(json({ user_id: "alice", active: false }));
      await expect(result).rejects.toMatchObject({ name: "AbortError" });
      expect(events).toEqual([]); expect(pendingMetadataAction("admin-one")).toBeNull();
    } finally { unsubscribe(); }
  });
  it("isolates another person's pending operation", async () => {
    const original = beginMetadataAction(spec(), "/v1/users/alice", "PUT"); releaseMetadataSender(original);
    setMetadataActor("admin-two");
    vi.stubGlobal("fetch", vi.fn(async () => json({ user_id: "alice", active: true }))); await write();
    expect(pendingMetadataAction("admin-one").request_id).toBe(original.request_id);
    expect(pendingMetadataAction("admin-two")).toBeNull();
  });
  it("does not send when checkpoint storage fails or a previous checkpoint is corrupt", async () => {
    vi.stubGlobal("fetch", vi.fn());
    storage.setItem(metadataActionKey("admin-one"), "corrupt");
    await expect(write()).rejects.toThrow("先核对原操作");
    storage.removeItem(metadataActionKey("admin-one"));
    storage.setItem = () => { throw new Error("disabled storage"); };
    await expect(write()).rejects.toThrow("会话存储");
    expect(fetch).not.toHaveBeenCalled();
  });
  it("cancellation before sending leaves no uncertain operation", async () => {
    const controller = new AbortController();
    const unsubscribe = subscribeMetadataActions(() => { if (pendingMetadataAction("admin-one")) controller.abort(new Error("cancel before send")); });
    vi.stubGlobal("fetch", vi.fn());
    try { await expect(api("/v1/users/alice", { method: "PUT", body: '{}', signal: controller.signal })).rejects.toThrow("cancel before send"); }
    finally { unsubscribe(); }
    expect(fetch).not.toHaveBeenCalled(); expect(pendingMetadataAction("admin-one")).toBeNull();
  });
  it("releases sender and timer even when cancelled checkpoint removal fails", async () => {
    vi.useFakeTimers(); const controller = new AbortController(); let original;
    storage.removeItem = () => { throw new Error("storage removal unavailable"); };
    const unsubscribe = subscribeMetadataActions(() => {
      original = pendingMetadataAction("admin-one");
      if (original) controller.abort(new Error("cancel before send"));
    });
    vi.stubGlobal("fetch", vi.fn());
    try {
      await expect(api("/v1/users/alice", { method: "PUT", body: '{}', timeoutMs: 1000, signal: controller.signal })).rejects.toThrow("storage removal unavailable");
      expect(metadataActionSending(original.request_id)).toBe(false);
      expect(vi.getTimerCount()).toBe(0); expect(fetch).not.toHaveBeenCalled();
    } finally { unsubscribe(); }
  });
  it("keeps explicitly identified protocols and local member mode independent", async () => {
    setMetadataActor(null); vi.stubGlobal("fetch", vi.fn(async () => json({})));
    await api("/v1/users/alice", { method: "PUT", body: '{}', headers: { "X-RCN-Request-ID": "existing-durable-id" } });
    expect(fetch.mock.calls.at(-1)[1].headers.get("X-RCN-Request-ID")).toBe("existing-durable-id");
    configureMemberClient(true); await write();
    expect(fetch.mock.calls.at(-1)[1].headers.has("X-RCN-Request-ID")).toBe(false);
  });
  it("rejects a wrong or unfinished receipt without discarding the original", () => {
    const original = beginMetadataAction(spec(), "/v1/users/alice", "PUT"); releaseMetadataSender(original);
    const receipt = { ...original, state: "completed", result: { user_id: "alice", active: false } };
    for (const patch of [{ request_id: "different" }, { kind: "feature_settings" }, { subject_id: "bob" }, { state: "pending" }, { state: "reconciliation_required" }, { result: null }, { result: [] }, { result: {} }, { result: { user_id: "bob" } }]) expect(() => validateMetadataReceipt({ ...receipt, ...patch }, original)).toThrow();
    const missing = { ...receipt }; delete missing.result;
    expect(() => validateMetadataReceipt(missing, original)).toThrow("不完整");
    expect(pendingMetadataAction("admin-one").request_id).toBe(original.request_id);
  });
  it("binds abandonment recovery to its original Unit, Attempt and external run without saving its reason", () => {
    const path = "/v1/admin/jobs/job-original/units/unit-original/abandon-and-retry";
    const request = { expected_attempt_id: "attempt-old", expected_external_run_id: "ssh-old", reason: "reason-is-not-a-checkpoint-field" };
    const original = beginMetadataAction(metadataActionSpec(path, "POST", JSON.stringify(request)), path, "POST"); releaseMetadataSender(original);
    expect(JSON.stringify(original)).not.toContain(request.reason);
    const result = { job_id: "job-original", work_unit_id: "unit-original", abandoned_attempt_id: "attempt-old", abandoned_external_run_id: "ssh-old", outcome: "queued" };
    const receipt = { ...original, state: "completed", result };
    expect(validateMetadataReceipt(receipt, original)).toEqual(result);
    for (const patch of [{ job_id: "other-job" }, { work_unit_id: "other-unit" }, { abandoned_attempt_id: "attempt-new" }, { abandoned_external_run_id: "ssh-new" }, { outcome: "running" }]) expect(() => validateMetadataReceipt({ ...receipt, result: { ...result, ...patch } }, original)).toThrow();
    expect(pendingMetadataAction("admin-one").request_id).toBe(original.request_id);
  });
  it("keeps incomplete scheduling results pending until both revision and policy arrive", () => {
    const path = "/v1/admin/scheduling/confirm";
    const original = beginMetadataAction(metadataActionSpec(path, "POST", '{}'), path, "POST"); releaseMetadataSender(original);
    for (const result of [{}, { revision: 2 }, { revision: 0, policy: {} }, { revision: 2, policy: [] }]) {
      expect(() => validateMetadataReceipt({ ...original, state: "completed", result }, original)).toThrow("调度策略回执不完整");
    }
    const result = { revision: 2, policy: { strategy: "balanced" } };
    expect(validateMetadataReceipt({ ...original, state: "completed", result }, original)).toEqual(result);
    expect(pendingMetadataAction("admin-one").request_id).toBe(original.request_id);
  });
});
