import fs from "node:fs";
import path from "node:path";
import { test, expect } from "@playwright/test";

const panel = page => page.getByRole("region", { name: "调度策略设置" });
const settingsPath = "/v1/settings/scheduling";
const shots = process.env.RCN_SCREENSHOT_DIR;

// Browser-only scheduling fixtures: no API request reaches a control plane.
async function mockControlShell(page) {
  await page.route("**/v1/**", route => {
    const pathname = new URL(route.request().url()).pathname;
    const responses = {
      "/v1/me": { actor_id: "fixture-admin", roles: ["admin"] },
      "/v1/overview": { generated_at: new Date().toISOString(), machines: [], summary: {} },
      "/v1/dispatcher/status": { process: { running: false, control_mode: "stopped" } },
      "/v1/settings/features": {}, "/v1/help/protected": {},
      "/v1/jobs": [], "/v1/operations/metrics": {}, "/v1/admin/control-runs": [],
      "/v1/release/identity": {}, "/v1/distribution/contract": {},
    };
    if (route.request().method() === "GET" && Object.hasOwn(responses, pathname)) {
      return route.fulfill({ json: responses[pathname] });
    }
    return route.fulfill({ status: 404, json: { detail: "isolated browser fixture" } });
  });
}

async function enter(page) {
  await page.goto("/app/control");
  await expect(page.getByRole("heading", { name: "任务分发策略", exact: true })).toBeVisible();
  await expect(panel(page).getByRole("radio")).toHaveCount(3);
}

async function chooseSmall(page, reason) {
  await panel(page).getByRole("radio", { name: /小批量优先/ }).check();
  const mode = panel(page).getByLabel("小批量判定方式", { exact: true });
  if (await mode.count()) await mode.selectOption("legacy");
  await panel(page).getByLabel("小批量最多单元数", { exact: true }).fill("3");
  await panel(page).getByLabel("变更原因", { exact: true }).fill(reason);
  await panel(page).getByRole("button", { name: "预览调度策略", exact: true }).click();
  await expect(panel(page).getByRole("button", { name: "确认应用策略", exact: true })).toBeVisible();
}

test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: "ignoreErrors" }); });

test("parallel minutes survive GET, preview and the identical confirmation", async ({ page }) => {
  await mockControlShell(page);
  const policy = { strategy: "small_batch_first", small_batch_max_units: 4,
    small_batch_max_serial_seconds: 1800, small_batch_max_parallel_seconds: 2460, starvation_after_s: 7200 };
  const previews = [], confirms = [];
  await page.route("**/v1/settings/scheduling", route => route.fulfill({ json: { revision: 7, parallel_small_batch_schema: 1, policy } }));
  await page.route("**/v1/admin/scheduling/preview", route => {
    previews.push(route.request().postDataJSON());
    return route.fulfill({ json: { confirmation_hash: "parallel-fixture-confirmation" } });
  });
  await page.route("**/v1/admin/scheduling/confirm", route => {
    const body = route.request().postDataJSON(); confirms.push(body);
    return route.fulfill({ json: { revision: 8, parallel_small_batch_schema: 1, policy: body.policy } });
  });
  await enter(page);
  const minutes = panel(page).getByLabel("小批量并行完工上限（分钟）", { exact: true });
  await expect(minutes).toHaveValue("41");
  await expect(panel(page).getByLabel("小批量最多单元数", { exact: true })).toHaveCount(0);
  await expect(panel(page).getByLabel("小批量总预计时长上限（秒）", { exact: true })).toHaveCount(0);
  await expect(panel(page)).toContainText("不按此刻空槽判断");
  await minutes.fill("45");
  await panel(page).getByLabel("变更原因", { exact: true }).fill("parallel wall-clock threshold");
  await panel(page).getByRole("button", { name: "预览调度策略", exact: true }).click();
  await expect(panel(page)).toContainText("并行完工上限 45 分钟");
  await panel(page).getByRole("button", { name: "确认应用策略", exact: true }).click();
  await expect(panel(page)).toContainText("策略已确认");
  expect(previews).toHaveLength(1); expect(confirms).toHaveLength(1);
  expect(previews[0].policy).toEqual({ ...policy, small_batch_max_parallel_seconds: 2700 });
  expect(confirms[0]).toEqual({ ...previews[0], confirmation_hash: "parallel-fixture-confirmation" });
  await expect(minutes).toHaveValue("45");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});

test("new capability enables parallel mode from legacy without changing legacy thresholds", async ({ page }) => {
  await mockControlShell(page);
  const policy = { strategy: "balanced", small_batch_max_units: 4,
    small_batch_max_serial_seconds: 1800, starvation_after_s: 7200 };
  let preview;
  await page.route("**/v1/settings/scheduling", route => route.fulfill({ json: { revision: 2, parallel_small_batch_schema: 1, policy } }));
  await page.route("**/v1/admin/scheduling/preview", route => {
    preview = route.request().postDataJSON();
    return route.fulfill({ json: { confirmation_hash: "enable-parallel-fixture" } });
  });
  await enter(page);
  await panel(page).getByLabel("小批量判定方式", { exact: true }).selectOption("parallel");
  await expect(panel(page).getByLabel("小批量并行完工上限（分钟）", { exact: true })).toHaveValue("41");
  await expect(panel(page).getByLabel("小批量最多单元数", { exact: true })).toHaveCount(0);
  await panel(page).getByLabel("变更原因", { exact: true }).fill("enable compatible parallel rule");
  await panel(page).getByRole("button", { name: "预览调度策略", exact: true }).click();
  await expect(panel(page)).toContainText("并行完工上限 41 分钟");
  expect(preview.policy).toEqual({ ...policy, small_batch_max_parallel_seconds: 2460 });
});

test("old API keeps legacy controls without adding an unsupported parallel field", async ({ page }) => {
  await mockControlShell(page);
  const policy = { strategy: "balanced", small_batch_max_units: 4,
    small_batch_max_serial_seconds: 1800, starvation_after_s: 7200 };
  let preview;
  await page.route("**/v1/settings/scheduling", route => route.fulfill({ json: { revision: 2, policy } }));
  await page.route("**/v1/admin/scheduling/preview", route => {
    preview = route.request().postDataJSON();
    return route.fulfill({ json: { confirmation_hash: "legacy-fixture" } });
  });
  await enter(page);
  await expect(panel(page).getByLabel("小批量判定方式", { exact: true })).toHaveCount(0);
  await chooseSmall(page, "old API compatibility");
  expect(preview.policy).not.toHaveProperty("small_batch_max_parallel_seconds");
  expect(preview.policy.small_batch_max_units).toBe(3);
});

test("real preview and confirm change strategy only for future assignments", async ({ page }, testInfo) => {
  const before = await (await page.request.get(settingsPath)).json();
  await enter(page);
  await chooseSmall(page, "isolated browser small batch acceptance");
  await expect(panel(page)).toContainText("不重排已分配的 Attempt");
  await panel(page).getByRole("button", { name: "确认应用策略", exact: true }).click();
  await expect(panel(page)).toContainText("策略已确认");
  const after = await (await page.request.get(settingsPath)).json();
  expect(after.revision).toBe(before.revision + 1);
  expect(after.policy.strategy).toBe("small_batch_first");
  expect(after.policy.small_batch_max_units).toBe(3);
  expect(after.running_attempts_unchanged).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  if (shots) await page.screenshot({ path: path.join(shots, `scheduling-${testInfo.project.name}.png`), fullPage: true });
});

test("lost successful confirmation retries the identical immutable request", async ({ page }) => {
  await enter(page);
  const bodies = []; let first = true;
  await page.route("**/v1/admin/scheduling/confirm", async route => {
    bodies.push(route.request().postDataJSON());
    const response = await route.fetch();
    if (first) { first = false; await route.fulfill({ status: 503, json: { detail: "fixture reply lost after persistence" } }); }
    else await route.fulfill({ response });
  });
  await chooseSmall(page, "isolated lost confirmation reply");
  await panel(page).getByRole("button", { name: "确认应用策略", exact: true }).click();
  await expect(panel(page).getByRole("alert")).toContainText("确认结果未完成核对");
  await expect(panel(page).getByRole("radio").first()).toBeDisabled();
  await panel(page).getByRole("button", { name: "确认应用策略", exact: true }).click();
  await expect(panel(page)).toContainText("策略已确认");
  expect(bodies).toHaveLength(2);
  expect(bodies[1]).toEqual(bodies[0]);
});

test("stale preview is refused and can be reconciled read-only", async ({ page }) => {
  await enter(page); await chooseSmall(page, "isolated stale preview");
  const current = await (await page.request.get(settingsPath)).json();
  const change = { expected_revision: current.revision, policy: { ...current.policy, strategy: "balanced" }, reason: "another authorized operator" };
  const preview = await (await page.request.post("/v1/admin/scheduling/preview", { data: change })).json();
  expect((await page.request.post("/v1/admin/scheduling/confirm", { data: { ...change, confirmation_hash: preview.confirmation_hash } })).ok()).toBe(true);
  await panel(page).getByRole("button", { name: "确认应用策略", exact: true }).click();
  await expect(panel(page).getByRole("alert")).toContainText("revision_conflict");
  await panel(page).getByRole("button", { name: "核对当前结果", exact: true }).click();
  await expect(panel(page)).toContainText("已读取中心当前策略");
  await expect(panel(page).getByRole("radio", { name: /公平均衡/ })).toBeChecked();
});

test("distribution identity and exported report contain no operational secrets", async ({ page }, testInfo) => {
  await enter(page);
  const section = page.getByRole("region", { name: "分发与发行身份" });
  await expect(section).toContainText("公共安装器");
  await expect(section).toContainText("私密身份");
  const pending = page.waitForEvent("download");
  await section.getByRole("button", { name: "导出脱敏诊断报告", exact: true }).click();
  const download = await pending;
  const target = testInfo.outputPath("sanitized-report.json"); await download.saveAs(target);
  const report = JSON.parse(fs.readFileSync(target, "utf8"));
  expect(Object.values(report.privacy).every(value => value === false)).toBe(true);
  expect(report.performs_remote_io).toBe(false); expect(report.performs_mutations).toBe(false);
  await expect(section).toContainText("仍含内部任务身份");
});

test("dark mode and unavailable identity preserve existing dispatcher controls", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await page.route("**/v1/release/identity", route => route.fulfill({ status: 503, json: { detail: "fixture identity temporarily unavailable" } }));
  await enter(page);
  await expect(page.getByRole("region", { name: "分发与发行身份" })).toContainText("内容暂时不可用");
  await expect(page.getByRole("button", { name: "启动", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});
