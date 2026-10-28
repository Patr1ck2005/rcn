import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { PairingApplicationForm, PairingStatus, pairingError, pairingFinished, pairingState, rememberPairingId, savedPairingId } from "./MemberPairing";
import { loadPairingDecisions, pairingApprovalChoice, pairingCodeMatches } from "./AdminMemberPairing";

const id = "11111111-2222-4333-8444-555555555555";
afterEach(() => vi.unstubAllGlobals());
describe("online member pairing", () => {
  it("requires completed Agent configuration and a passing doctor before declaring readiness", () => {
    const approved = { state: "approved", phase: "connected", agent_configuration: {}, doctor_state: "completed" };
    expect(pairingFinished({ state: "approved" })).toBe(false);
    expect(pairingFinished({ ...approved, doctor: { ok: false } })).toBe(false);
    expect(pairingState({ ...approved, doctor_state: "started" })).toBe("failed");
    expect(pairingFinished({ ...approved, doctor: { ok: true } })).toBe(true);
    expect(pairingState({ ...approved, phase: "personal_login_saved" })).toBe("configuring");
  });
  it("persists only the original UUID and ignores invalid checkpoints", () => {
    const setItem = vi.fn(); const removeItem = vi.fn();
    vi.stubGlobal("localStorage", { setItem, removeItem, getItem: () => id });
    rememberPairingId(id); expect(setItem).toHaveBeenCalledWith("rcn-member-pairing", id); expect(savedPairingId()).toBe(id);
    rememberPairingId(null); expect(removeItem).toHaveBeenCalledWith("rcn-member-pairing");
    vi.stubGlobal("localStorage", { getItem: () => "not-a-uuid" });
    vi.stubGlobal("sessionStorage", { getItem: () => { throw new Error("denied"); } });
    expect(savedPairingId()).toBeNull();
  });
  it("offers a single application form without requesting credentials", () => {
    const html = renderToStaticMarkup(<PairingApplicationForm draft={{ center_url: "", name: "", device_name: "", target: "codex", label: "研究助手" }} onChange={() => {}} onSubmit={() => {}} />);
    for (const text of ["课题组中心链接", "你的姓名", "设备名称", "申请加入课题组", "Claude Code", "研究助手"]) expect(html).toContain(text);
    expect(html).not.toContain("personal_token"); expect(html).not.toContain('type="password"');
  });
  it("shows the original application and human verification instructions while pending", () => {
    const html = renderToStaticMarkup(<MemoryRouter><PairingStatus record={{ pairing_id: id, state: "pending", name: "小林", device_name: "笔记本", short_code: "A1B2C3" }} /></MemoryRouter>);
    for (const text of [id, "A1B2C3", "本人联系渠道", "每 5 秒", "恢复原申请"]) expect(html).toContain(text);
    expect(html).not.toContain("复制指令给 Agent");
  });
  it("uses safe actionable errors without echoing arbitrary server details", () => {
    expect(pairingError({ reasonCode: "member_pairing_rate_limited" })).toContain("一分钟");
    expect(pairingError({ message: "password=must-not-render" })).not.toContain("must-not-render");
    expect(pairingError({ reasonCode: "member_pairing_content_conflict" })).toContain("原申请");
  });
  it("distinguishes DNS, certificates, TLS, Tunnel and origin service failures", () => {
    for (const [reasonCode, clue] of [["center_dns_unavailable", "域名"], ["center_certificate_invalid", "证书"], ["center_tls_failed", "HTTPS 握手"], ["center_tunnel_unavailable", "Tunnel"], ["center_origin_unavailable", "回源服务"], ["center_gateway_tls_failed", "回源证书"]]) {
      const message = pairingError({ reasonCode }); expect(message).toContain(clue); expect(message).toContain("原申请"); expect(message).not.toContain("重装");
    }
  });
});
describe("explicit administrative identity selection", () => {
  it("does not infer a member identity from a name or a short code", () => {
    expect(pairingApprovalChoice("", "same-name-member")).toBeNull();
    expect(pairingApprovalChoice("existing", "")).toBeNull();
    expect(pairingApprovalChoice("new", "same-name-member")).toEqual({ create_new: true });
    expect(pairingApprovalChoice("existing", "member-123")).toEqual({ create_new: false, member_id: "member-123" });
    expect(pairingCodeMatches("ABC123", " abc123 ")).toBe(true);
    expect(pairingCodeMatches("ABC123", "ABC124")).toBe(false);
  });
  it("restores only recognized original decision checkpoints", () => {
    vi.stubGlobal("sessionStorage", { getItem: () => JSON.stringify({ [id]: { action: "approve", body: { create_new: true } }, invalid: { action: "approve" } }) });
    expect(loadPairingDecisions("admin")).toEqual({ [id]: { action: "approve", body: { create_new: true } } });
    vi.stubGlobal("sessionStorage", { getItem: () => "not-json" }); expect(loadPairingDecisions("admin")).toEqual({});
  });
});
