import path from "node:path";
import { expect, test } from "@playwright/test";
import { memberApiFixture, selectTaskPackage } from "./member-client.fixture";

async function expectNoOverflow(page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
}

test("archive retrieval stays visible and browsing never starts another transfer", async ({ page }) => {
  const fixture = await memberApiFixture(page);
  fixture.operations.set("restore-original", {
    operation_id: "restore-original", phase: "collecting", job_id: "job-alice-1",
    job: { status: "completed", completed_units: 2, total_units: 2 },
    collection: { state: "downloading", stage: "restore_pending", verified_files: 1, total_files: 2 },
    collection_control: { state: "active" }, can_confirm: false, can_upload: false, can_collect: false,
  });
  await page.goto("/app/runs");
  await expect(page.locator(".member-badge")).toHaveText("等待归档取回");
  await expect(page.getByText("保留原下载记录和已核验文件。", { exact: false })).toBeVisible();
  await expect(page.getByRole("button", { name: "暂停结果下载" })).toBeVisible();
  expect(fixture.calls.filter((call) => call.method !== "GET")).toEqual([]);
  expect(fixture.jobsCreated()).toBe(0);
  await expectNoOverflow(page);
});

for (const mode of ["https", "managed-ssh"]) {
  // Frontend compatibility contract only: the current broker uses ordinary
  // HTTPS and does not emit configured_connection or accept rcn-managed URIs.
  test(`compatibility-only preconfigured ${mode} UI hides channel details and preserves the original submission`, async ({ page }) => {
    const fixture = await memberApiFixture(page, { connected: false });
    const reference = "rcn-managed://11111111-2222-4333-8444-555555555555/" + "a".repeat(64);
    const configured_connection = { mode, center_reference: reference };
    const logins = [];
    let session = { connected: false, center_url: reference, configured_connection };
    await page.route("**/local/v1/session", async (route) => {
      if (route.request().method() === "POST") {
        logins.push(route.request().postDataJSON());
        session = { ...session, connected: true, online: true, actor: { actor_id: "member-alice", roles: ["member"] } };
      } else if (route.request().method() === "DELETE") session = { ...session, connected: false, actor: null };
      return route.fulfill({ json: session });
    });
    await page.goto("/connect");
    await page.getByText("高级恢复：使用已有个人登录信息", { exact: true }).click();
    await expect(page.getByLabel("管理员预配置的中心连接")).toHaveValue("课题组计算中心");
    await expect(page.getByLabel("中心 HTTPS 地址")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText(reference);
    await page.getByLabel("个人访问 token").fill("private-member-test-token");
    await page.getByRole("button", { name: "连接并进入" }).click();
    await expect(page.getByRole("heading", { name: "连接与 Agent 配置", exact: true })).toBeVisible();
    await page.getByRole("link", { name: "继续提交任务", exact: true }).click();
    await expect(page.getByRole("heading", { name: "提交科研任务" })).toBeVisible();
    expect(logins).toEqual([{ center_url: reference, token: "private-member-test-token" }]);
    await expect(page.locator("body")).not.toContainText(reference);
    await selectTaskPackage(page);
    await page.getByRole("button", { name: "生成提交预览", exact: true }).click();
    await page.getByRole("button", { name: "确认提交", exact: true }).click();
    await expect(page.getByRole("link", { name: "job-alice-1", exact: true })).toBeVisible();
    const operation = await page.locator("[data-operation-id]").getAttribute("data-operation-id");
    await page.reload(); await selectTaskPackage(page);
    await expect(page.locator("[data-operation-id]")).toHaveAttribute("data-operation-id", operation);
    expect(fixture.jobsCreated()).toBe(1);
    if (await page.getByRole("button", { name: "打开导航", exact: true }).isVisible()) await page.getByRole("button", { name: "打开导航", exact: true }).click();
    await page.getByRole("button", { name: "退出个人登录" }).click();
    await page.getByText("高级恢复：使用已有个人登录信息", { exact: true }).click();
    await expect(page.getByLabel("管理员预配置的中心连接")).toBeVisible();
    await expect(page.getByLabel("个人访问 token")).toHaveValue("");
    await expectNoOverflow(page);
  });
}

test("unselected connection keeps HTTPS in advanced recovery and performs no automatic login", async ({ page }) => {
  await memberApiFixture(page, { connected: false });
  const logins = [];
  await page.route("**/local/v1/session", async (route) => {
    if (route.request().method() === "POST") logins.push(route.request().postDataJSON());
    return route.fulfill({ json: { connected: false, center_url: "", configured_connection: null } });
  });
  await page.goto("/connect");
  await page.getByText("高级恢复：使用已有个人登录信息", { exact: true }).click();
  await expect(page.getByLabel("中心 HTTPS 地址")).toHaveValue("");
  await expect(page.getByLabel("管理员预配置的中心连接")).toHaveCount(0);
  expect(logins).toEqual([]);
  await page.getByLabel("中心 HTTPS 地址").fill("http://127.0.0.1:28765");
  await page.getByLabel("个人访问 token").fill("private-member-test-token");
  await page.getByRole("button", { name: "连接并进入" }).click();
  expect(logins).toEqual([]);
  await page.getByLabel("中心 HTTPS 地址").fill("https://compute.example.org");
  await page.getByRole("button", { name: "连接并进入" }).click();
  await expect.poll(() => logins.length).toBe(1);
  expect(logins[0].center_url).toBe("https://compute.example.org");
});

test("member connection uses the local session and never persists a personal token in browser storage", async ({ page }) => {
  const fixture = await memberApiFixture(page, { connected: false });
  await page.addInitScript(() => sessionStorage.setItem("rcn-pilot-token", "old-central-test-token"));
  await page.goto("/connect");
  await page.getByText("高级恢复：使用已有个人登录信息", { exact: true }).click();
  await page.getByLabel("中心 HTTPS 地址").fill("https://compute.example.org");
  await page.getByLabel("个人访问 token").fill("private-member-test-token");
  await page.getByRole("button", { name: "连接并进入" }).click();
  await expect(page.getByRole("heading", { name: "连接与 Agent 配置", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "继续提交任务", exact: true }).click();
  await expect(page.getByRole("heading", { name: "提交科研任务" })).toBeVisible();
  const sessionRequest = fixture.calls.find((call) => call.pathname === "/local/v1/session" && call.method === "POST");
  expect(JSON.parse(sessionRequest.body)).toEqual({ center_url: "https://compute.example.org", token: "private-member-test-token" });
  expect(fixture.calls.every((call) => !call.headers.authorization)).toBe(true);
  expect(await page.evaluate(() => ({ ...sessionStorage }))).toEqual({ "rcn-pilot-token": "old-central-test-token" });
  expect(await page.evaluate(() => ({ ...localStorage }))).toEqual({});
  if (await page.getByRole("button", { name: "打开导航", exact: true }).isVisible()) await page.getByRole("button", { name: "打开导航", exact: true }).click();
  await page.getByRole("button", { name: "退出个人登录" }).click();
  await expect(page.getByRole("heading", { name: "连接与 Agent 配置", exact: true })).toBeVisible();
  await expect(page.getByLabel("个人访问 token")).toHaveValue("");
});

test("task ZIP proceeds through preview, one Job, upload, verified collection, and client restart", async ({ page }, testInfo) => {
  const fixture = await memberApiFixture(page);
  await page.goto("/app/submit");
  await selectTaskPackage(page);
  await expect(page.getByRole("heading", { name: "任务包预览" })).toBeVisible();
  const imported = fixture.calls.find((call) => call.pathname === "/local/v1/packages");
  expect(imported.headers["content-type"]).toBe("application/zip");
  expect(decodeURIComponent(imported.headers["x-rcn-filename"])).toBe("研究任务.zip");
  await page.getByRole("button", { name: "生成提交预览", exact: true }).click();
  await page.getByRole("button", { name: "确认提交", exact: true }).click();
  await expect(page.getByRole("link", { name: "job-alice-1", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "上传 / 继续上传" }).click();
  await expect(page.getByText("计算进度：2 / 2 单元")).toBeVisible();
  await page.getByRole("button", { name: "下载并核验结果" }).click();
  await expect(page.getByText("结果已下载并通过校验")).toBeVisible();
  await expect(page.getByText(/本机目录/)).toContainText("job-alice-1");
  await page.getByRole("button", { name: "核对原提交" }).click();
  expect(fixture.jobsCreated()).toBe(1);
  const ids = fixture.calls.filter((call) => call.pathname.endsWith("/confirm")).map((call) => call.pathname);
  expect(new Set(ids).size).toBe(1);
  await page.goto("/app/runs"); await page.reload();
  await expect(page.getByText("结果已下载并通过校验")).toBeVisible();
  await expectNoOverflow(page);
  if (process.env.RCN_SCREENSHOT_DIR) await page.screenshot({ path: path.join(process.env.RCN_SCREENSHOT_DIR, `member-results-${testInfo.project.name}.png`), fullPage: true });
});

test("lost confirmation and upload replies recover the original operation without new jobs", async ({ page }) => {
  const fixture = await memberApiFixture(page, { lostConfirm: true, lostUpload: true });
  await page.goto("/app/submit"); await selectTaskPackage(page);
  await page.getByRole("button", { name: "生成提交预览", exact: true }).click();
  await page.getByRole("button", { name: "确认提交", exact: true }).click();
  await expect(page.getByText("响应中断，已恢复原提交记录。")).toBeVisible();
  await expect(page.getByRole("link", { name: "job-alice-1", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "上传 / 继续上传" }).click();
  await expect(page.getByText("计算进度：2 / 2 单元")).toBeVisible();
  expect(fixture.jobsCreated()).toBe(1);
  expect(fixture.calls.filter((call) => call.pathname.endsWith("/confirm"))).toHaveLength(1);
  expect(fixture.calls.filter((call) => call.pathname.endsWith("/upload"))).toHaveLength(1);
});

test("missing duration requires an explicit unit count and does not invent a duration", async ({ page }) => {
  const fixture = await memberApiFixture(page, { missingPartition: true });
  await page.goto("/app/submit"); await selectTaskPackage(page);
  await expect(page.getByRole("heading", { name: "补充分包信息" })).toBeVisible();
  await page.getByLabel("请求计算单元数").fill("4");
  await page.getByRole("button", { name: "生成提交预览", exact: true }).click();
  const request = fixture.calls.find((call) => call.method === "PUT");
  expect(JSON.parse(request.body)).toEqual({ package_id: "package-alice", requested_unit_count: 4 });
  expect(fixture.operations.values().next().value.preview.estimated_duration_seconds).toBeNull();
  await expectNoOverflow(page);
});

test("revoked project rights are surfaced without repeating confirmation", async ({ page }) => {
  const fixture = await memberApiFixture(page, { revoked: true });
  await page.goto("/app/submit"); await selectTaskPackage(page);
  await page.getByRole("button", { name: "生成提交预览", exact: true }).click();
  await page.getByRole("button", { name: "确认提交", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("项目提交授权已撤销");
  expect(fixture.jobsCreated()).toBe(0);
  expect(fixture.calls.filter((call) => call.pathname.endsWith("/confirm"))).toHaveLength(1);
});

for (const scenario of [{ option: "foreignPackage", message: "任务包提交身份与当前成员不匹配" }, { option: "damagedPackage", message: "任务包校验失败：输入文件哈希不匹配" }]) {
  test(`invalid package stops before planning: ${scenario.option}`, async ({ page }) => {
    const fixture = await memberApiFixture(page, { [scenario.option]: true });
    await page.goto("/app/submit"); await selectTaskPackage(page);
    await expect(page.getByRole("alert")).toContainText(scenario.message);
    await expect(page.getByRole("button", { name: "生成提交预览", exact: true })).toHaveCount(0);
    expect(fixture.operations.size).toBe(0);
  });
}

test("rerun is deliberate and creates a preview without automatically creating another Job", async ({ page }) => {
  const fixture = await memberApiFixture(page);
  await page.goto("/app/submit"); await selectTaskPackage(page);
  await page.getByRole("button", { name: "生成提交预览", exact: true }).click();
  await page.getByRole("button", { name: "确认提交", exact: true }).click();
  const originalId = [...fixture.operations.keys()][0];
  await page.getByRole("button", { name: "重新计算…", exact: true }).click();
  expect(fixture.operations.size).toBe(1);
  await page.getByRole("button", { name: "返回原任务" }).click();
  expect(fixture.operations.size).toBe(1);
  await page.getByRole("button", { name: "重新计算…", exact: true }).click();
  await page.getByRole("button", { name: "生成新提交预览" }).click();
  await expect(page.getByRole("button", { name: "确认提交", exact: true })).toBeVisible();
  expect(fixture.operations.size).toBe(2);
  expect(fixture.jobsCreated()).toBe(1);
  expect([...fixture.operations.keys()][1]).not.toBe(originalId);
});

test("reimporting the same ZIP restores the original submission after a page restart", async ({ page }) => {
  const fixture = await memberApiFixture(page);
  await page.goto("/app/submit"); await selectTaskPackage(page);
  await page.getByRole("button", { name: "生成提交预览", exact: true }).click();
  await page.getByRole("button", { name: "确认提交", exact: true }).click();
  await expect(page.getByRole("link", { name: "job-alice-1", exact: true })).toBeVisible();
  const original = await page.locator("[data-operation-id]").getAttribute("data-operation-id");
  await page.reload(); await selectTaskPackage(page);
  await expect(page.getByRole("link", { name: "job-alice-1", exact: true })).toBeVisible();
  await expect(page.locator("[data-operation-id]")).toHaveAttribute("data-operation-id", original);
  await expect(page.getByRole("button", { name: "生成提交预览", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "确认提交", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "核对原提交" }).click();
  expect(fixture.jobsCreated()).toBe(1);
  expect(fixture.calls.filter((call) => call.method === "PUT")).toHaveLength(1);
});

test("optional contribution requires consent and resource edits preserve owner pause", async ({ page }) => {
  const fixture = await memberApiFixture(page);
  await page.goto("/app/contribution");
  await expect(page.getByRole("button", { name: "同意并接入计算" })).toBeDisabled();
  await page.getByLabel("私密 v2 机器邀请").fill("private-test-invite");
  await expect(page.getByLabel("计算工作目录")).toHaveAttribute("readonly");
  await expect(page.getByLabel("计算工作目录")).toHaveValue("C:\\ProgramData\\ResearchComputeNetwork\\MemberNodes\\member-alice\\worker");
  await page.getByLabel("最多调度 CPU 线程").fill("4");
  await page.getByLabel("我同意在所设资源范围内贡献计算").check();
  await page.getByRole("button", { name: "同意并接入计算" }).click();
  await expect(page.getByRole("heading", { name: "MEMBER-ALICE" })).toBeVisible();
  await page.getByRole("button", { name: "暂停接活", exact: true }).click();
  await expect(page.getByText("已暂停接活", { exact: true })).toBeVisible();
  await page.getByLabel("内存预算（MiB）").fill("2048");
  await page.getByRole("button", { name: "保存资源预算与时间" }).click();
  await expect(page.getByText("已暂停接活", { exact: true })).toBeVisible();
  const edit = fixture.calls.filter((call) => call.pathname.endsWith("/preferences")).at(-1);
  expect(JSON.parse(edit.body)).toMatchObject({ max_cpus: 4, max_memory_mb: 2048, min_free_disk_mb: 10240, reserved_cpu_percent: 25 });
  expect(JSON.parse(edit.body)).not.toHaveProperty("paused");
  await expectNoOverflow(page);
});

test("member flow remains readable in dark mode", async ({ page }, testInfo) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await memberApiFixture(page);
  await page.goto("/app/submit"); await selectTaskPackage(page);
  await expect(page.getByRole("heading", { name: "任务包预览" })).toBeVisible();
  await expectNoOverflow(page);
  if (process.env.RCN_SCREENSHOT_DIR) await page.screenshot({ path: path.join(process.env.RCN_SCREENSHOT_DIR, `member-import-dark-${testInfo.project.name}.png`), fullPage: true });
});

test("offline cached identity can pause locally while remote submit and resume stay disabled", async ({ page }) => {
  const fixture = await memberApiFixture(page, { online: false,
    contribution: { configured: true, machine_id: "MEMBER-ALICE", preferences: { paused: false, max_cpus: 4, max_memory_mb: 4096, memory_reserve_mb: 1024 } } });
  await page.goto("/app/submit");
  await expect(page.getByText("当前离线，保留本机身份与提交记录。", { exact: true })).toBeVisible();
  await selectTaskPackage(page);
  await expect(page.getByRole("button", { name: "生成提交预览" })).toBeDisabled();
  await page.getByRole("link", { name: "管理本机计算与暂停" }).click();
  await expect(page.getByRole("heading", { name: "MEMBER-ALICE" })).toBeVisible();
  await expect(page.getByRole("button", { name: "保存资源预算与时间" })).toBeDisabled();
  await page.getByRole("button", { name: "暂停接活", exact: true }).click();
  await expect(page.getByText("已暂停接活", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "恢复接活", exact: true })).toBeDisabled();
  await page.reload();
  await expect(page.getByRole("button", { name: "恢复接活", exact: true })).toBeDisabled();
  const writes = fixture.calls.filter((call) => ["POST", "PUT"].includes(call.method));
  expect(writes.map((call) => call.pathname)).toEqual(["/local/v1/packages", "/local/v1/contribution/preferences"]);
  const { operation_id, expected_revision, ...pause } = JSON.parse(writes.at(-1).body);
  expect(pause).toEqual({ paused: true });
  expect(operation_id).toMatch(/^[0-9a-f-]{36}$/);
  expect(expected_revision).toBe(0);
  await expectNoOverflow(page);
});
