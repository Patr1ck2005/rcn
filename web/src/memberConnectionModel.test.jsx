import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import MemberConnectionSetup from "./MemberConnectionSetup";
import { connectionError, importComplete, importPreview, importRunning, pendingConnectionImport, rememberConnectionImport, sanitizedDoctorReport, uploadConnectionBundle } from "./memberConnectionModel";

afterEach(() => vi.unstubAllGlobals());
describe("member connection imports and diagnostics", () => {
  it("keeps help, import and a real diagnostic action available with unreadable configuration", () => {
    const html = renderToStaticMarkup(<MemoryRouter><MemberConnectionSetup session={null} error="配置损坏" onSession={() => {}} /></MemoryRouter>);
    for (const text of ["帮助与文档", "选择私密连接包", "重新自检", "配置损坏", "/app/help/member-getting-started"]) expect(html).toContain(text);
    expect(html).not.toContain("独立 Agent token");
  });
  it("distinguishes preview, execution, unknown and completion", () => {
    expect(importPreview({ state: "preview" })).toBe(true);
    expect(importRunning({ state: "configuring" })).toBe(true);
    expect(importRunning({ state: "unknown" })).toBe(false);
    expect(importComplete({ state: "completed" })).toBe(true);
  });
  it("persists only the original non-secret operation ID and tolerates denied storage", () => {
    const setItem = vi.fn(); vi.stubGlobal("sessionStorage", { setItem, getItem: () => "import-123", removeItem: vi.fn() });
    rememberConnectionImport("import-123"); expect(setItem).toHaveBeenCalledWith("rcn-connection-import", "import-123");
    expect(pendingConnectionImport()).toBe("import-123");
    vi.stubGlobal("sessionStorage", { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); } });
    expect(pendingConnectionImport()).toBe(null); expect(() => rememberConnectionImport("import-123")).not.toThrow();
  });
  it("uploads the raw ZIP without a JSON wrapper or authorization header", async () => {
    const fetcher = vi.fn(async () => ({ ok: true, json: async () => ({ import_id: "import-123", state: "preview" }) })); vi.stubGlobal("fetch", fetcher);
    await uploadConnectionBundle(new File(["synthetic-test-only"], "connection.rcn"));
    const [path, options] = fetcher.mock.calls[0]; expect(path).toBe("/local/v1/connection-imports");
    expect(options.body).toBeInstanceOf(File); expect(options.body.name).toBe("connection.rcn"); expect(options.headers).toEqual({ "Content-Type": "application/zip", "X-RCN-Filename": "connection.rcn" });
  });
  it("exports only sanitized structured evidence, preserving skipped and warning states", () => {
    const report = sanitizedDoctorReport({ ok: false, token: "not-exported", session: { private_key: "not-exported" }, diagnostic_id: "diagnostic-1", summary: "Bearer synthetic-secret", checks: [
      { stage: "config", status: "warning", reason_code: "local_config_invalid", message: "token=synthetic-secret", next_action: "https://name:password@center.example/fix?token=abc", help_slug: "member-connection", secret: "not-exported" },
      { stage: "identity", status: "skipped", message: "not checked", help_slug: "../private" },
    ], next_actions: ["password=synthetic-secret"] });
    expect(report.checks.map((item) => item.status)).toEqual(["warning", "skipped"]);
    expect(report.checks[1].help_slug).toBe(null);
    expect(JSON.stringify(report)).not.toMatch(/synthetic-secret|not-exported|name:password|token=abc/);
    expect(report.checks[0].next_action).toBe("https://center.example/fix");
  });
  it("uses stable failure codes for actionable Chinese guidance", () => {
    expect(connectionError({ reasonCode: "ssh_host_key_mismatch", message: "opaque" })).toContain("主机指纹");
    expect(connectionError({ reasonCode: "connection_bundle_expired" })).toContain("重新签发");
    expect(connectionError(new TypeError("Failed to fetch"))).toContain("本机服务或网络");
  });
});
