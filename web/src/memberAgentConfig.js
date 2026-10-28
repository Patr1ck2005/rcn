export const memberAgentTargets = {
  codex: { label: "Codex", entry: "AGENTS.md" },
  claude: { label: "Claude Code", entry: "CLAUDE.md" },
  dsh: { label: "DSH", entry: "AGENTS.md" },
  generic: { label: "其他 Agent", entry: "现有项目说明文件" },
};

export function memberIdentityVerified(session) {
  return Boolean(session?.connected && session?.actor?.actor_id
    && session.online === true && session.remote_actions_available === true);
}

export function validateMemberAgentBundle(value, session, target, agentId) {
  const files = ["rcn-agent-access.json", "AGENT_ACCESS.md", `${target.toUpperCase()}_SETUP.md`];
  if (!memberIdentityVerified(session) || !memberAgentTargets[target]
    || value?.schema_version !== 1 || value.target !== target
    || value.agent_id !== agentId || value.independent_credential !== true
    || value.actor_id !== session.actor.actor_id || value.center_url !== session.center_url
    || value.identity_verified !== true || value.credential_included !== false
    || value.filename !== `RCN-Agent-${target}.zip` || value.media_type !== "application/zip"
    || !Array.isArray(value.files) || value.files.length > 30
    || files.some((name) => !value.files.includes(name))
    || new Set(value.files).size !== value.files.length
    || value.files.some((name) => typeof name !== "string" || name.length > 180
      || name.includes("..") || /[\\:]/.test(name) || name.startsWith("/")
      || (!files.includes(name) && !/^[a-zA-Z0-9_./-]+\.md$/i.test(name)))
    || typeof value.content_base64 !== "string" || value.content_base64.length > 262144
    || !/^[A-Za-z0-9+/]+={0,2}$/.test(value.content_base64)
    || typeof value.setup_instructions !== "string" || value.setup_instructions.length > 100000
    || /-----BEGIN [^-]*PRIVATE KEY-----|\bBearer\s+[a-zA-Z0-9._-]{12,}|\b(?:access_token|personal_token|password|private_key)\s*[:=]\s*["']?[^\s"']{8,}/i.test(value.setup_instructions)
    || Object.keys(value || {}).some((key) => /^(?:token|access_token|personal_token|password|private_key|secret)$/i.test(key))) {
    throw new Error("配置与当前已核验身份不一致，请重新自检后生成。");
  }
  return value;
}

export function downloadMemberAgentBundle(bundle) {
  const raw = atob(bundle.content_base64);
  const url = URL.createObjectURL(new Blob([Uint8Array.from(raw, (character) => character.charCodeAt(0))], { type: bundle.media_type }));
  const link = document.createElement("a");
  link.href = url; link.download = bundle.filename;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
