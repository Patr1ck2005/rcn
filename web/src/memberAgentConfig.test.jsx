import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import MemberAgentSetup from "./MemberAgentSetup";
import { memberIdentityVerified, validateMemberAgentBundle } from "./memberAgentConfig";

const session = { connected: true, online: true, remote_actions_available: true,
  actor: { actor_id: "member-a", roles: ["member"] }, center_url: "https://center.example" };
const agentId = "11111111-2222-4333-8444-555555555555";
const bundle = (target = "codex") => ({ schema_version: 1, target, actor_id: "member-a",
  agent_id: agentId, independent_credential: true,
  center_url: session.center_url, identity_verified: true, credential_included: false,
  filename: `RCN-Agent-${target}.zip`, media_type: "application/zip",
  files: ["rcn-agent-access.json", "AGENT_ACCESS.md", `${target.toUpperCase()}_SETUP.md`],
  content_base64: "UEsBAg==", setup_instructions: "Use the existing project instructions." });

describe("installed member connection and Agent setup", () => {
  it("requires a current online identity and distinguishes cached login", () => {
    expect(memberIdentityVerified(session)).toBe(true);
    expect(memberIdentityVerified({ ...session, online: false })).toBe(false);
    expect(memberIdentityVerified({ ...session, remote_actions_available: false })).toBe(false);
    expect(memberIdentityVerified({ ...session, actor: null })).toBe(false);
  });
  it.each(["codex", "claude", "dsh", "generic"])("accepts only the selected %s adapter bound to the current person", (target) => {
    const value = bundle(target);
    expect(validateMemberAgentBundle(value, session, target, agentId)).toBe(value);
    expect(() => validateMemberAgentBundle(value, { ...session, actor: { actor_id: "member-b" } }, target, agentId)).toThrow();
    expect(() => validateMemberAgentBundle(value, { ...session, center_url: "https://another.example" }, target, agentId)).toThrow();
    expect(() => validateMemberAgentBundle({ ...value, credential_included: true }, session, target, agentId)).toThrow();
    expect(() => validateMemberAgentBundle({ ...value, filename: "../escape.zip" }, session, target, agentId)).toThrow();
    expect(() => validateMemberAgentBundle({ ...value, files: [...value.files, "secret.txt"] }, session, target, agentId)).toThrow();
    expect(() => validateMemberAgentBundle({ ...value, independent_credential: false }, session, target, agentId)).toThrow();
    expect(() => validateMemberAgentBundle({ ...value, agent_id: "another-agent" }, session, target, agentId)).toThrow();
    expect(validateMemberAgentBundle({ ...value, files: [...value.files, "guidance/RECOVERY.md"] }, session, target, agentId).files).toContain("guidance/RECOVERY.md");
    expect(() => validateMemberAgentBundle({ ...value, token: "never-export-this" }, session, target, agentId)).toThrow();
    expect(() => validateMemberAgentBundle({ ...value, setup_instructions: "Bearer do-not-export-a-real-secret" }, session, target, agentId)).toThrow();
  });
  it("renders identity confirmation, a real self-check action and all three export targets", () => {
    const html = renderToStaticMarkup(<MemoryRouter><MemberAgentSetup session={session} onSession={() => {}} /></MemoryRouter>);
    for (const text of ["member-a", "中心已核验", "重新自检", "我确认使用上方个人身份", "Codex", "Claude Code", "DSH", "配置不包含个人 token", "保留原有项目规则"]) expect(html).toContain(text);
    expect(html).toMatch(/disabled=""[^>]*>生成 Codex 配置/);
    expect(html).toContain("其他 Agent");
    expect(html).not.toContain('aria-label="独立 Agent token"');
  });
});
