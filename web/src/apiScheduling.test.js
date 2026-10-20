import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const flush = async () => { for (let i = 0; i < 8; i += 1) await Promise.resolve(); };
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

let client;
beforeEach(async () => {
  vi.resetModules();
  const stored = new Map();
  vi.stubGlobal("sessionStorage", {
    getItem: (key) => stored.get(key) || null,
    setItem: (key, value) => stored.set(key, value),
    removeItem: (key) => stored.delete(key),
  });
  client = await import("./api");
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

// A response whose headers have arrived but whose JSON is still being read.
function heldReads() {
  const bodies = [];
  let hold = true;
  vi.stubGlobal("fetch", vi.fn((path) => {
    if (!hold) return Promise.resolve(new Response(JSON.stringify({ path }), { status: 200 }));
    const body = deferred();
    bodies.push(body);
    return Promise.resolve({ ok: true, status: 200, json: () => body.promise });
  }));
  return () => { hold = false; bodies.forEach((body) => body.resolve({ ready: true })); };
}

describe("scheduled API reads", () => {
  it("holds one slot through body parsing and preserves critical URLs and authorization", async () => {
    client.setToken("test-person-a");
    const release = heldReads();
    const paths = ["/v1/settings", "/v1/jobs?view=compact&limit=50", "/v1/me", "/v1/overview", "/v1/operations/insights?scope=visible", "/v1/jobs/job-a"];
    const reads = paths.map((path) => client.api(path));
    await flush();
    expect(fetch.mock.calls.map(([path]) => path)).toEqual([paths[2]]);
    expect(fetch.mock.calls.every(([, options]) => options.headers.get("Authorization") === "Bearer test-person-a")).toBe(true);
    await flush();
    expect(fetch).toHaveBeenCalledTimes(1);
    release();
    await Promise.all(reads);
    expect(fetch.mock.calls.map(([path]) => path)).toEqual([paths[2], paths[1], paths[4], paths[5], paths[0], paths[3]]);
  });

  it("treats HEAD as a bounded read and preserves the existing empty-response contract", async () => {
    const release = heldReads();
    const active = [client.api("/v1/active-0", { timeoutMs: 0 })];
    await flush();
    const head = client.api("/v1/probe", { method: "HEAD" });
    await flush();
    expect(fetch).toHaveBeenCalledTimes(1);
    release();
    fetch.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await Promise.all(active);
    await expect(head).resolves.toBeNull();
    expect(fetch.mock.calls.at(-1)[1].method).toBe("HEAD");
  });

  it("aborts queued and already-aborted reads promptly without making network requests", async () => {
    const release = heldReads();
    const active = [client.api("/v1/active-0", { timeoutMs: 0 })];
    await flush();
    const controller = new AbortController();
    const queued = expect(client.api("/v1/canceled", { signal: controller.signal })).rejects.toThrow("cancel queued");
    controller.abort(new Error("cancel queued"));
    await queued;
    await expect(client.api("/v1/already-canceled", { signal: controller.signal })).rejects.toThrow("cancel queued");
    expect(fetch).toHaveBeenCalledTimes(1);
    release();
    await Promise.all(active);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("counts queue wait against the API timeout without later fetching the expired read", async () => {
    vi.useFakeTimers();
    const release = heldReads();
    const active = [client.api("/v1/active-0", { timeoutMs: 0 })];
    await flush();
    const queued = expect(client.api("/v1/expired", { timeoutMs: 100 })).rejects.toThrow("请求超时");
    await vi.advanceTimersByTimeAsync(100);
    await queued;
    expect(fetch).toHaveBeenCalledTimes(1);
    release();
    await Promise.all(active);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(["fetch", "status", "json"])("releases a failed %s request before starting its queued successor", async (failure) => {
    const release = heldReads();
    const active = [client.api("/v1/active-0", { timeoutMs: 0 })];
    await flush();
    const failed = expect(client.api("/v1/failing")).rejects.toThrow();
    const next = client.api("/v1/success");
    release();
    if (failure === "fetch") fetch.mockRejectedValueOnce(new Error("network unavailable"));
    else if (failure === "status") fetch.mockResolvedValueOnce(new Response('{"detail":"denied"}', { status: 403 }));
    else fetch.mockResolvedValueOnce(new Response("invalid json", { status: 200 }));
    await Promise.all([...active, failed]);
    await expect(next).resolves.toEqual({ path: "/v1/success" });
  });

  it("lets writes, SSE and local capability discovery bypass occupied read slots", async () => {
    const release = heldReads();
    const active = [client.api("/v1/active-0", { timeoutMs: 0 })];
    await flush();
    fetch.mockImplementation((path) => {
      if (path === "/v1/events/stream") return Promise.resolve(new Response("", { status: 200 }));
      if (path === "/local/v1/capabilities") return Promise.resolve(new Response("", { status: 404 }));
      return Promise.resolve(new Response('{"accepted":true}', { status: 200 }));
    });
    await expect(client.api("/v1/control", { method: "POST", body: "{}" })).resolves.toEqual({ accepted: true });
    await expect(client.connectStateStream(vi.fn(), vi.fn(), new AbortController().signal)).resolves.toBe(0);
    await expect(client.detectMemberClient()).resolves.toBeNull();
    expect(fetch.mock.calls.slice(1).map(([path]) => path)).toEqual(["/v1/control", "/v1/events/stream", "/local/v1/capabilities"]);
    release();
    await Promise.all(active);
  });

  it.each(["token", "member-mode"])("rejects queued reads when the %s identity changes and uses the new identity for new reads", async (change) => {
    client.setToken("test-person-a");
    const release = heldReads();
    const active = [expect(client.api("/v1/active-0", { timeoutMs: 0 })).rejects.toMatchObject({ name: "AbortError", message: "身份已变更，请重新读取" })];
    await flush();
    const queued = expect(client.api("/v1/old-actor")).rejects.toMatchObject({ name: "AbortError", message: "身份已变更，请重新读取" });
    if (change === "token") client.setToken("test-person-b");
    else client.configureMemberClient(true);
    await queued;
    const fresh = client.api("/v1/new-actor");
    release();
    await Promise.all(active);
    await fresh;
    expect(fetch.mock.calls.some(([path]) => path === "/v1/old-actor")).toBe(false);
    const freshHeaders = fetch.mock.calls.find(([path]) => path === "/v1/new-actor")[1].headers;
    expect(freshHeaders.get("Authorization")).toBe(change === "token" ? "Bearer test-person-b" : null);
  });

  it.each(["token", "member-mode"])("rejects an active body from the old %s identity and releases its slot for the new identity", async (change) => {
    client.setToken("test-person-a");
    const release = heldReads();
    const oldRead = expect(client.api("/v1/old-active")).rejects.toMatchObject({ name: "AbortError", message: "身份已变更，请重新读取" });
    await flush();
    expect(fetch.mock.calls.map(([path]) => path)).toEqual(["/v1/old-active"]);
    if (change === "token") client.setToken("test-person-b");
    else client.configureMemberClient(true);
    const fresh = client.api("/v1/new-active");
    await flush();
    expect(fetch).toHaveBeenCalledTimes(1);
    release();
    await oldRead;
    await expect(fresh).resolves.toEqual({ path: "/v1/new-active" });
    expect(fetch.mock.calls.map(([path]) => path)).toEqual(["/v1/old-active", "/v1/new-active"]);
    const freshHeaders = fetch.mock.calls[1][1].headers;
    expect(freshHeaders.get("Authorization")).toBe(change === "token" ? "Bearer test-person-b" : null);
  });

  it.each(["GET", "HEAD"])("rejects an old-identity 204 %s response before returning its empty body", async (method) => {
    client.setToken("test-person-a");
    const headers = deferred();
    vi.stubGlobal("fetch", vi.fn(() => headers.promise));
    const oldRead = expect(client.api("/v1/empty-active", { method })).rejects.toMatchObject({ name: "AbortError", message: "身份已变更，请重新读取" });
    await flush();
    expect(fetch).toHaveBeenCalledTimes(1);
    client.setToken("test-person-b");
    headers.resolve(new Response(null, { status: 204 }));
    await oldRead;
  });

  it.each(["token", "member-mode"])("preserves an audited write receipt when the %s identity changes during body parsing", async (change) => {
    client.setToken("test-person-a");
    const release = heldReads();
    const write = client.api("/v1/control", { method: "POST", body: "{}" });
    await flush();
    expect(fetch).toHaveBeenCalledTimes(1);
    if (change === "token") client.setToken("test-person-b");
    else client.configureMemberClient(true);
    release();
    await expect(write).resolves.toEqual({ ready: true });
  });
});
