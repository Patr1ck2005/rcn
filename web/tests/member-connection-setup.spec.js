import { expect, test } from "@playwright/test";
import { memberApiFixture } from "./member-client.fixture";

const importedSession = { connected: true, online: true, remote_actions_available: true, center_url: "https://compute.example.org", actor: { actor_id: "member-alice", roles: ["member"] } };
const preview = { owner_user_id: "member-alice", center_name: "课题组计算中心", mode: "managed-ssh" };
const ready = { import_id: "import-original-123", state: "awaiting_confirmation", preview };
const report = { ok: false, diagnostic_id: "doctor-original", summary: "连接待恢复", checks: [
  { stage: "local_config", status: "passed", message: "本机配置可读取" },
  { stage: "transport", status: "failed", reason_code: "center_unreachable", message: "中心不可达", next_action: "检查网络后重试", help_slug: "member-connection" },
  { stage: "identity", status: "skipped", message: "连接恢复后核验" },
  { stage: "ssh", status: "failed", reason_code: "member_openssh_missing", message: "SSH 客户端尚未就绪", next_action: "恢复本机连接组件" },
], next_actions: ["检查网络后重试"] };

async function helpFixture(page) {
  const article = { slug: "member-connection", title: "成员连接与诊断", summary: "本机接入说明", category: "workflow", section: "成员接入", html: "<p>导入连接包后，运行本机诊断。</p>" };
  await page.route("**/v1/help/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    return route.fulfill({ json: path.endsWith("/catalog") ? { public: [article], protected: [] } : path.endsWith("/public") ? [article] : article });
  });
}
async function clipboardFixture(page) {
  await page.addInitScript(() => { Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (value) => { window.__copied = value; } } }); });
}

test("unreadable local configuration still exposes logged-out help and click-triggered diagnostics", async ({ page }, testInfo) => {
  await memberApiFixture(page, { connected: false }); await helpFixture(page); await clipboardFixture(page);
  await page.route("**/local/v1/session", (route) => route.fulfill({ status: 422, json: { detail: { reason_code: "local_config_invalid", message: "invalid configuration" } } }));
  const doctors = [];
  await page.route("**/local/v1/doctor", (route) => { doctors.push(route.request().postDataJSON()); return route.fulfill({ json: { ...report, token: "must-not-copy", session: { private_key: "must-not-copy" } } }); });
  await page.goto("/app/help/member-connection");
  await expect(page.getByRole("heading", { name: "成员连接与诊断", exact: true })).toBeVisible();
  expect(doctors).toEqual([]);
  await page.goto("/app/setup");
  await expect(page.getByRole("button", { name: "重新自检", exact: true })).toBeEnabled();
  expect(doctors).toEqual([]);
  await page.getByRole("button", { name: "重新自检", exact: true }).click();
  await expect(page.getByLabel("连接检查结果")).toContainText("未检查");
  await page.screenshot({ path: testInfo.outputPath("connection-diagnostics.png"), fullPage: true });
  await page.getByRole("button", { name: "复制诊断给 Agent", exact: true }).click();
  const copied = await page.evaluate(() => window.__copied);
  expect(JSON.parse(copied).diagnostic_id).toBe("doctor-original"); expect(copied).not.toContain("must-not-copy");
  const download = page.waitForEvent("download"); await page.getByRole("button", { name: "下载诊断 JSON", exact: true }).click();
  expect((await download).suggestedFilename()).toBe("RCN-connection-diagnostics.json");
  expect(doctors).toEqual([{ repair: false }]);
  await expect(page.getByRole("button", { name: "执行建议的本机安全修复", exact: true })).toBeDisabled();
  await page.getByLabel("按本次自检建议执行允许的本机安全修复。").check();
  await page.getByRole("button", { name: "执行建议的本机安全修复", exact: true }).click();
  await expect.poll(() => doctors.length).toBe(2); expect(doctors[1]).toEqual({ repair: true });
});

test("private import preview, double-click guard and same-ID recovery never replay an unknown confirmation", async ({ page }) => {
  await memberApiFixture(page, { connected: false }); await helpFixture(page);
  let uploads = 0; let confirms = 0; let reads = 0; let allowRead = false;
  await page.route("**/local/v1/connection-imports**", async (route) => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    if (path.endsWith("/confirm")) { confirms += 1; await new Promise((resolve) => setTimeout(resolve, 100)); return route.abort("failed"); }
    if (request.method() === "POST") {
      uploads += 1; expect(request.headers()["content-type"]).toBe("application/zip"); expect(request.postData()).toBe("synthetic-connection-bundle");
      return route.fulfill({ json: ready });
    }
    reads += 1;
    if (!allowRead) return route.abort("failed");
    return route.fulfill({ json: { ...ready, state: "completed", session: importedSession, stages: [{ stage: "identity", status: "passed", message: "身份已核验" }] } });
  });
  await page.goto("/app/setup");
  await page.getByLabel("选择私密连接包", { exact: true }).setInputFiles({ name: "member.rcn", mimeType: "application/json", buffer: Buffer.from("synthetic-connection-bundle") });
  await expect(page.locator(".member-import-status").getByText("member-alice", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "确认并接入中心", exact: true })).toBeDisabled();
  await page.getByLabel("我确认连接包属于本人，并将使用上方中心与身份。").check();
  await page.getByRole("button", { name: "确认并接入中心", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(page.getByText("结果待确认", { exact: true })).toBeVisible();
  expect(confirms).toBe(1); expect(reads).toBe(1); expect(uploads).toBe(1);
  await expect(page.getByLabel("选择私密连接包", { exact: true })).toBeDisabled();
  allowRead = true;
  await page.evaluate(() => sessionStorage.clear());
  await page.reload();
  await expect(page.getByRole("heading", { name: "连接已完成", exact: true })).toBeVisible();
  await expect(page.getByLabel("导入阶段")).toContainText("身份已核验");
  await expect(page.getByLabel("使用的 Agent", { exact: true })).toBeVisible();
  expect(confirms).toBe(1); expect(uploads).toBe(1); expect(reads).toBe(2);
  expect(await page.evaluate(() => sessionStorage.getItem("rcn-connection-import"))).toBe(null);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});

test("failed import shows actionable code and retries the original ID", async ({ page }) => {
  await memberApiFixture(page, { connected: false }); let confirms = 0;
  await page.route("**/local/v1/connection-imports**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/confirm")) { confirms += 1; return route.fulfill({ json: confirms === 1 ? { ...ready, state: "failed", error: { reason_code: "ssh_host_key_mismatch", message: "mismatch" } } : { ...ready, state: "completed", session: importedSession } }); }
    return route.fulfill({ json: ready });
  });
  await page.goto("/app/setup");
  await page.getByLabel("选择私密连接包", { exact: true }).setInputFiles({ name: "member.rcn", mimeType: "application/json", buffer: Buffer.from("synthetic") });
  await page.getByLabel("我确认连接包属于本人，并将使用上方中心与身份。").check();
  await page.getByRole("button", { name: "确认并接入中心", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "主机指纹" })).toBeVisible();
  await page.getByRole("button", { name: "按原编号重试导入", exact: true }).click();
  await expect(page.getByRole("heading", { name: "连接已完成", exact: true })).toBeVisible(); expect(confirms).toBe(2);
});

test("a read-back interrupted commit can explicitly continue the same import", async ({ page }) => {
  await memberApiFixture(page, { connected: false });
  await page.addInitScript(() => localStorage.setItem("rcn-connection-import", "import-original-123"));
  let confirms = 0;
  await page.route("**/local/v1/connection-imports**", (route) => {
    if (route.request().method() === "POST") { confirms += 1; return route.fulfill({ json: { ...ready, state: "completed", session: importedSession } }); }
    return route.fulfill({ json: { ...ready, state: "committing" } });
  });
  await page.goto("/app/setup");
  await expect(page.getByRole("heading", { name: "正在保存连接与身份", exact: true })).toBeVisible();
  expect(confirms).toBe(0);
  await page.getByLabel("我确认连接包属于本人，并将使用上方中心与身份。").check();
  await page.getByRole("button", { name: "继续原导入", exact: true }).click();
  await expect(page.getByRole("heading", { name: "连接已完成", exact: true })).toBeVisible();
  expect(confirms).toBe(1);
});

test("one-click generic Agent config copies instructions and independently revokes the original credential", async ({ page }, testInfo) => {
  await memberApiFixture(page); await clipboardFixture(page);
  let agent = null; const writes = [];
  await page.route("**/local/v1/agent-configurations**", (route) => {
    if (route.request().method() === "POST") { writes.push(new URL(route.request().url()).pathname); agent = { ...agent, registration_state: "revoked", configured: false }; return route.fulfill({ json: { center_token_revoked: true } }); }
    return route.fulfill({ json: { agents: agent ? [agent] : [] } });
  });
  await page.route("**/local/v1/agent-instructions", (route) => {
    const body = route.request().postDataJSON(); expect(Object.keys(body).sort()).toEqual(["agent_id", "label", "target"]); expect(body.target).toBe("generic");
    agent = { ...body, configured: true, credential_id: "credential-generic-1" };
    return route.fulfill({ json: { schema_version: 1, target: body.target, actor_id: "member-alice", center_url: importedSession.center_url, agent_id: body.agent_id, independent_credential: true,
      identity_verified: true, credential_included: false, filename: "RCN-Agent-generic.zip", media_type: "application/zip", files: ["rcn-agent-access.json", "AGENT_ACCESS.md", "GENERIC_SETUP.md", "guidance/RECOVERY.md"],
      content_base64: Buffer.from("PK-synthetic-fixture").toString("base64"), setup_instructions: "Read AGENT_ACCESS.md and preserve existing rules." } });
  });
  await page.goto("/app/setup"); await page.getByLabel("我确认使用上方个人身份配置 Agent。").check();
  await page.getByLabel("使用的 Agent", { exact: true }).selectOption("generic");
  await expect(page.getByLabel("独立 Agent token")).toHaveCount(0);
  await page.getByRole("button", { name: "生成 其他 Agent 配置", exact: true }).click();
  await page.getByRole("button", { name: "复制接入说明", exact: true }).click();
  expect(await page.evaluate(() => window.__copied)).toBe("Read AGENT_ACCESS.md and preserve existing rules.");
  await page.screenshot({ path: testInfo.outputPath("agent-configured.png"), fullPage: true });
  const download = page.waitForEvent("download"); await page.getByRole("button", { name: "下载配置 ZIP", exact: true }).click(); expect((await download).suggestedFilename()).toBe("RCN-Agent-generic.zip");
  await page.getByText("停用此 Agent", { exact: true }).click();
  await expect(page.getByRole("button", { name: "撤销此 Agent 的中心凭据", exact: true })).toBeDisabled();
  await page.getByLabel("确认撤销 我的 其他 Agent 的独立中心凭据。").check();
  await page.getByRole("button", { name: "撤销此 Agent 的中心凭据", exact: true }).click();
  await expect(page.getByText("此 Agent 的中心凭据已撤销，桌面个人登录和其他 Agent 不受影响。")).toBeVisible();
  await expect(page.getByRole("button", { name: "生成 其他 Agent 配置", exact: true })).toBeDisabled();
  expect(writes).toEqual([`/local/v1/agent-configurations/${agent.agent_id}/revoke`]);
});

test("cached offline identity can still open public help", async ({ page }) => {
  await memberApiFixture(page, { online: false }); await helpFixture(page);
  await page.goto("/app/help/member-connection");
  await expect(page.getByRole("heading", { name: "成员连接与诊断", exact: true })).toBeVisible();
  await expect(page.getByText("中心连接未确认", { exact: true })).toBeVisible();
});
