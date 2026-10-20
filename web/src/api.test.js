import { afterEach, describe, expect, it, vi } from "vitest";

import { api, configureMemberClient, connectStateStream, detectMemberClient, parseSseFrames, setToken, token } from "./api";

afterEach(() => {
  configureMemberClient(false);
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("member client identity boundary", () => {
  it("detects the explicit local mode before making authenticated requests", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ mode: "member-client", schema_version: 1 }), { status: 200 })));
    await expect(detectMemberClient()).resolves.toMatchObject({ mode: "member-client" });
    expect(fetch).toHaveBeenCalledWith("/local/v1/capabilities", expect.objectContaining({ cache: "no-store", signal: expect.any(AbortSignal) }));
  });
  it("does not read, migrate, or store browser tokens in member mode", async () => {
    const storage = { getItem: vi.fn(() => "old-browser-secret"), setItem: vi.fn(), removeItem: vi.fn() };
    vi.stubGlobal("sessionStorage", storage);
    configureMemberClient(true);
    expect(token()).toBe(""); setToken("new-personal-secret");
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 200 })));
    await api("/v1/me", { headers: { Authorization: "Bearer should-not-leave-browser" } });
    expect(fetch.mock.calls[0][1].headers.has("Authorization")).toBe(false);
    expect(storage.getItem).not.toHaveBeenCalled();
    expect(storage.setItem).not.toHaveBeenCalled();
    expect(storage.removeItem).not.toHaveBeenCalled();
  });
  it("keeps central browser token compatibility after a missing local endpoint", async () => {
    vi.stubGlobal("sessionStorage", { getItem: () => "central-session-token" });
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 404 })));
    await expect(detectMemberClient()).resolves.toBeNull();
    expect(token()).toBe("central-session-token");
  });
  it("does not fall back to central authentication when local discovery fails", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 503 })));
    await expect(detectMemberClient()).rejects.toThrow("无法读取客户端状态");
  });
});

describe("bounded reads", () => {
  it("aborts a stalled read and allows the next request", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("sessionStorage", { getItem: () => null });
    vi.stubGlobal("fetch", vi.fn((path, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener("abort", () => reject(options.signal.reason));
    })));
    const result = expect(api("/v1/overview", { timeoutMs: 100 })).rejects.toThrow("请求超时");
    await vi.advanceTimersByTimeAsync(100); await result;
    fetch.mockResolvedValue(new Response('{}', { status: 200 }));
    await expect(api("/v1/overview")).resolves.toEqual({});
    expect(fetch.mock.calls.at(-1)[1].cache).toBe("no-store");
    expect(vi.getTimerCount()).toBe(0);
  });
  it("retains the caller abort signal and does not time out writes by default", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("sessionStorage", { getItem: () => null });
    vi.stubGlobal("fetch", vi.fn((path, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener("abort", () => reject(options.signal.reason));
    })));
    const controller = new AbortController();
    const result = expect(api("/control", { method: "POST", signal: controller.signal })).rejects.toThrow("cancelled");
    expect(vi.getTimerCount()).toBe(0);
    controller.abort(new Error("cancelled")); await result;
  });
});

describe("parseSseFrames", () => {
  it("parses connected and state frames while retaining a partial tail", () => {
    const parsed = parseSseFrames(
      'event: connected\ndata: {"latest_sequence":7}\n\n' +
      'id: 8\nevent: state\ndata: {"event_id":"event-8",\n' +
      'data: "sequence":8}\n\n' +
      "event: state\ndata: {",
    );
    expect(parsed.events).toEqual([
      { type: "connected", id: null, payload: { latest_sequence: 7 } },
      { type: "state", id: 8, payload: { event_id: "event-8", sequence: 8 } },
    ]);
    expect(parsed.remainder).toBe("event: state\ndata: {");
  });

  it("ignores keepalives and malformed JSON", () => {
    const parsed = parseSseFrames(": keepalive\n\nevent: state\ndata: nope\n\n");
    expect(parsed.events).toEqual([]);
  });

  it("backs off during a coordinated center release without advancing the state cursor", async () => {
    vi.stubGlobal("sessionStorage", { getItem: () => "" });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      'retry: 5000\nevent: maintenance\ndata: {"reason_code":"release_draining"}\n\n',
      { status: 200, headers: { "Content-Type": "text/event-stream" } },
    )));
    const onState = vi.fn();
    await expect(connectStateStream(onState, vi.fn(), new AbortController().signal, { lastSequence: 19 }))
      .rejects.toMatchObject({ retryAfterMs: 5000 });
    expect(onState).not.toHaveBeenCalled();
  });

  it("returns a snapshot resume cursor when the connected handler resets the baseline", async () => {
    vi.stubGlobal("sessionStorage", {
      getItem: () => "",
      setItem: () => {},
      removeItem: () => {},
    });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      'event: connected\ndata: {"latest_sequence":7}\n\n',
      { status: 200, headers: { "Content-Type": "text/event-stream" } },
    )));

    const statuses = [];
    const result = await connectStateStream(
      async (event) => ({ resume_sequence: event.latest_sequence }),
      (status) => statuses.push(status),
      new AbortController().signal,
      { lastSequence: 99 },
    );

    expect(result).toBe(7);
    expect(statuses).toEqual(["connected"]);
  });
});

describe("structured restrictions", () => {
  it("keeps the reason and next-action payload on API errors", async () => {
    vi.stubGlobal("sessionStorage", {
      getItem: () => "",
      setItem: () => {},
      removeItem: () => {},
    });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      detail: { reason_code: "project_owner_required", message: "owner required" },
      restriction: {
        reason_code: "project_owner_required",
        message: "该功能存在，但当前身份尚未获得所需权限。",
        next_action: "向项目 owner 申请",
      },
    }), { status: 403, headers: { "Content-Type": "application/json" } })));

    await expect(api("/v1/projects/example")).rejects.toMatchObject({
      status: 403,
      message: "owner required 下一步：向项目 owner 申请",
      reasonCode: "project_owner_required",
      restriction: { next_action: "向项目 owner 申请" },
    });
  });
});


describe("bounded startup discovery", () => {
  it("times out a hung local service and permits an explicit retry", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", vi.fn((path, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener("abort", () => reject(options.signal.reason));
    })));
    const result = expect(detectMemberClient({ timeoutMs: 100 })).rejects.toThrow("客户端状态超时");
    await vi.advanceTimersByTimeAsync(100); await result;
    fetch.mockResolvedValueOnce(new Response("", { status: 404 }));
    await expect(detectMemberClient({ timeoutMs: 100 })).resolves.toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });
});
