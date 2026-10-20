import { expect, test } from "@playwright/test";
import { memberApiFixture } from "./member-client.fixture";

function bundle(target, actor = "member-alice", agentId = "11111111-2222-4333-8444-555555555555") {
  return { schema_version: 1, target, actor_id: actor, center_url: "https://compute.example.org",
    agent_id: agentId, independent_credential: true,
    identity_verified: true, credential_included: false, filename: `RCN-Agent-${target}.zip`,
    media_type: "application/zip", files: ["rcn-agent-access.json", "AGENT_ACCESS.md", `${target.toUpperCase()}_SETUP.md`],
    content_base64: Buffer.from("PK-browser-contract-fixture").toString("base64"),
    setup_instructions: `Read AGENT_ACCESS.md using ${target}; no personal credential is included.` };
}

test("HTTPS login enters identity/self-check/Agent export and requires explicit identity confirmation", async ({ page }) => {
  const fixture = await memberApiFixture(page, { connected: false });
  const generated = [];
  const agents = [];
  await page.route("**/local/v1/agent-configurations**", (route) => {
    if (route.request().method() === "DELETE") {
      const id = new URL(route.request().url()).pathname.split("/").at(-1);
      agents.find((item) => item.agent_id === id).configured = false;
      return route.fulfill({ json: { local_login_removed: true, center_token_revoked: false } });
    }
    return route.fulfill({ json: { agents } });
  });
  await page.route("**/local/v1/agent-instructions", async (route) => {
    const body = route.request().postDataJSON(); generated.push(body);
    await new Promise((resolve) => setTimeout(resolve, 50));
    if (!agents.some((item) => item.agent_id === body.agent_id)) agents.push({ agent_id: body.agent_id, label: body.label, target: body.target, configured: true, credential_id: `token-${body.target}` });
    return route.fulfill({ json: bundle(body.target, "member-alice", body.agent_id) });
  });
  await page.goto("/connect");
  await page.getByLabel("中心 HTTPS 地址").fill("https://compute.example.org");
  await page.getByLabel("个人访问 token").fill("synthetic-HTTPS-wizard-token");
  await page.getByRole("button", { name: "连接并进入", exact: true }).click();
  await expect(page).toHaveURL(/\/app\/setup$/);
  await expect(page.getByRole("heading", { name: "连接与 Agent 配置", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "生成 Codex 配置", exact: true })).toBeDisabled();
  const reads = fixture.calls.filter((call) => call.pathname === "/local/v1/session" && call.method === "GET").length;
  await page.getByRole("button", { name: "重新自检", exact: true }).click();
  await expect.poll(() => fixture.calls.filter((call) => call.pathname === "/local/v1/session" && call.method === "GET").length).toBeGreaterThan(reads);
  await page.getByLabel("我确认使用上方个人身份配置 Agent。").check();
  for (const [target, label] of [["codex", "Codex"], ["claude", "Claude Code"], ["dsh", "DSH"]]) {
    await page.getByLabel("Agent 实例", { exact: true }).selectOption("new");
    await page.getByLabel("使用的 Agent", { exact: true }).selectOption(target);
    await page.getByLabel("独立 Agent token", { exact: true }).fill(`synthetic-independent-${target}-token`);
    const generate = page.getByRole("button", { name: `生成 ${label} 配置`, exact: true });
    await generate.evaluate((button) => { button.click(); button.click(); });
    await expect(page.getByRole("button", { name: "下载配置 ZIP", exact: true })).toBeVisible();
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "下载配置 ZIP", exact: true }).click();
    expect((await download).suggestedFilename()).toBe(`RCN-Agent-${target}.zip`);
  }
  expect(generated.map((item) => item.target)).toEqual(["codex", "claude", "dsh"]);
  expect(new Set(generated.map((item) => item.agent_id)).size).toBe(3);
  expect(new Set(generated.map((item) => item.token)).size).toBe(3);
  await page.getByLabel("Agent 实例", { exact: true }).selectOption(generated[0].agent_id);
  await expect(page.getByText("token-codex", { exact: true })).toBeVisible();
  await expect(page.getByLabel("独立 Agent token", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "生成 Codex 配置", exact: true }).click();
  await expect.poll(() => generated.length).toBe(4);
  expect(generated[3].agent_id).toBe(generated[0].agent_id);
  expect(generated[3]).not.toHaveProperty("token");
  await page.getByRole("button", { name: "移除此 Agent 的本机登录", exact: true }).click();
  await expect(page.getByText("已移除此 Agent 的本机加密登录。中心 token 仍需管理员按原签发记录单独撤销。")).toBeVisible();
  await expect(page.getByLabel("独立 Agent token", { exact: true })).toHaveValue("");
  expect(await page.evaluate(() => ({ ...sessionStorage }))).toEqual({});
  expect(await page.evaluate(() => ({ ...localStorage }))).toEqual({});
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await page.getByRole("link", { name: "继续提交任务", exact: true }).click();
  await expect(page.getByRole("heading", { name: "提交科研任务", exact: true })).toBeVisible();
});

test("failed live self-check hides a generated bundle and disables further export", async ({ page }) => {
  await memberApiFixture(page);
  await page.route("**/local/v1/agent-instructions", (route) => route.fulfill({ json: bundle("codex", "member-alice", route.request().postDataJSON().agent_id) }));
  await page.goto("/app/setup");
  await page.getByLabel("我确认使用上方个人身份配置 Agent。").check();
  await page.getByLabel("独立 Agent token", { exact: true }).fill("synthetic-independent-token");
  await page.getByRole("button", { name: "生成 Codex 配置", exact: true }).click();
  await expect(page.getByRole("button", { name: "下载配置 ZIP", exact: true })).toBeVisible();
  await page.route("**/local/v1/session", (route) => route.fulfill({ json: { connected: true,
    actor: { actor_id: "member-alice", roles: ["member"] }, center_url: "https://compute.example.org",
    online: false, remote_actions_available: false, connection_error: { reason_code: "center_login_required" } } }));
  await page.getByRole("button", { name: "重新自检", exact: true }).click();
  await expect(page.getByText("个人身份或中心连接尚未确认，请重新登录或恢复网络后自检。")).toBeVisible();
  await expect(page.getByRole("button", { name: "下载配置 ZIP", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "生成 Codex 配置", exact: true })).toBeDisabled();
});

test("a reply for another personal identity cannot become a downloadable configuration", async ({ page }) => {
  await memberApiFixture(page);
  await page.route("**/local/v1/agent-instructions", (route) => route.fulfill({ json: bundle("codex", "member-bob", route.request().postDataJSON().agent_id) }));
  await page.goto("/app/setup");
  await page.getByLabel("我确认使用上方个人身份配置 Agent。").check();
  await page.getByLabel("独立 Agent token", { exact: true }).fill("synthetic-independent-token");
  await page.getByRole("button", { name: "生成 Codex 配置", exact: true }).click();
  await expect(page.getByText("配置与当前已核验身份不一致，请重新自检后生成。")).toBeVisible();
  await expect(page.getByRole("button", { name: "下载配置 ZIP", exact: true })).toHaveCount(0);
});
