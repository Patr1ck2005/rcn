import { build } from "esbuild";
import { expect, test } from "@playwright/test";

let bundle;
test.beforeAll(async () => {
  bundle = (await build({ entryPoints: ["src/main.jsx"], bundle: true, write: false, outdir: "ignored-in-memory",
    jsx: "automatic", define: { "process.env.NODE_ENV": '"production"' } })).outputFiles;
});
const GiB = 1024 ** 3;
const snapshot = () => ({ schema: 1, generated_at: "2026-10-23T06:00:00Z", basis: "registered_manifest_bytes",
  backfill_complete: true, unattributed_device_bytes: null, coverage: "Synthetic registered manifest coverage",
  volumes: [{ host_id: "center", volume_id: "F:", physical_device_id: "test-disk", free_bytes: 10 * GiB,
    total_bytes: 100 * GiB, reserved_bytes: GiB, hard_reserve_bytes: 10 * GiB, usable_bytes: 0,
    sample_count: 8, sampled_at: new Date().toISOString(), growth_bytes_per_day: GiB, days_to_reserve: 0 }],
  operation_continuations: [{ operation_id: "restore-original", state: "deferred", next_action: "核对原回执" }],
  projects: [{ project_id: "synthetic-project", role: "origin_spool", location: "center", bytes: 6 * GiB,
    pending_custody_bytes: 0, eligible_bytes: 2 * GiB, confirmed_retired_bytes: GiB }], growth_24h: [],
});

async function fixture(page, options = {}) {
  const state = { roles: ["admin", "member"], calls: [], offline: false, inventory: snapshot(), ...options };
  await page.route("**/*", async (route) => {
    const request = route.request(), url = new URL(request.url());
    state.calls.push({ path: url.pathname, method: request.method() });
    const json = (value, status = 200) => route.fulfill({ status, json: value });
    if (url.pathname === "/bundle.js" || url.pathname === "/bundle.css") return route.fulfill({ contentType: url.pathname.endsWith("js") ? "application/javascript" : "text/css", body: bundle.find((file) => file.path.endsWith(url.pathname.endsWith("js") ? ".js" : ".css")).text });
    if (url.pathname === "/local/v1/capabilities") return json({}, 404);
    if (url.pathname === "/v1/events/stream") return route.abort();
    if (url.pathname === "/v1/me") return json({ actor_id: "synthetic-admin", roles: state.roles });
    if (url.pathname === "/v1/settings/features") return json({ visibility: "full" });
    if (url.pathname === "/v1/overview") return json({ machines: [], policies: {}, summary: {} });
    if (url.pathname === "/v1/admin/storage/status") throw new Error("dashboard must not invoke synchronous device/history probes");
    if (url.pathname === "/v1/admin/storage/inventory") {
      await new Promise((resolve) => setTimeout(resolve, 120));
      return state.offline ? json({ detail: "synthetic inventory offline" }, 503) : json(state.inventory);
    }
    if (url.pathname.startsWith("/v1/")) return json([]);
    return route.fulfill({ contentType: "text/html", body: '<html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/bundle.css"><div id="root"></div><script src="/bundle.js"></script></html>' });
  });
  await page.goto(`http://rcn-storage.test/app/admin?tab=${state.tab || "users"}`);
  return state;
}
const storageCalls = (state) => state.calls.filter((call) => call.path.startsWith("/v1/admin/storage/"));

test("Storage loads only on selection, stays read only and retains a failed refresh", async ({ page }, testInfo) => {
  const state = await fixture(page);
  await expect(page.getByRole("heading", { name: "用户与角色", exact: true })).toBeVisible();
  expect(storageCalls(state)).toEqual([]);
  await page.getByRole("button", { name: "存储 Storage", exact: true }).click();
  await expect(page.getByRole("status", { name: "正在加载存储快照", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "存储概况", exact: true })).toBeVisible();
  await expect(page.getByText("90% 软告警", { exact: false })).toBeVisible();
  await expect(page.getByRole("row", { name: /synthetic-project/ })).toContainText("6 GiB");
  await expect(page.getByText("restore-original", { exact: true })).toBeVisible();
  expect(storageCalls(state)).toEqual([{ path: "/v1/admin/storage/inventory", method: "GET" }]);
  expect(storageCalls(state).every((call) => call.method === "GET")).toBe(true);
  expect(state.calls.some((call) => /restore|preparation|\/v1\/jobs/.test(call.path))).toBe(false);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  const tableRegion = page.getByRole("region", { name: "项目存储账目，可横向滚动" });
  await tableRegion.focus();
  await expect(tableRegion).toBeFocused();
  if (await tableRegion.evaluate((element) => element.scrollWidth > element.clientWidth)) {
    await tableRegion.press("ArrowRight");
    await expect.poll(() => tableRegion.evaluate((element) => element.scrollLeft)).toBeGreaterThan(0);
  }
  await page.evaluate(() => { window.scrollTo(0, 0); document.querySelector(".storage-table-wrap")?.scrollTo(0, 0); });
  await page.screenshot({ path: testInfo.outputPath("storage-light.png"), fullPage: true });
  await page.emulateMedia({ colorScheme: "dark" });
  await page.screenshot({ path: testInfo.outputPath("storage-dark.png"), fullPage: true });
  state.offline = true;
  await page.locator(".app-page .page-actions").getByRole("button", { name: "刷新", exact: true }).click();
  await expect(page.getByText(/刷新失败：synthetic inventory offline/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "存储概况", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "用户与 Token", exact: true }).click();
  await expect(page.getByRole("heading", { name: "用户与角色", exact: true })).toBeVisible();
  const reads = storageCalls(state).length;
  await page.waitForTimeout(250);
  expect(storageCalls(state)).toHaveLength(reads);
});

test("a partial snapshot keeps available evidence and unknown byte categories honest", async ({ page }) => {
  const state = await fixture(page, { tab: "storage", inventory: { ...snapshot(), backfill_complete: false, projects: [{ project_id: "partial-project", role: "origin_spool", bytes: 0 }] } });
  await expect(page.getByText("部分覆盖 / 回填待完成", { exact: true })).toBeVisible();
  const row = page.getByRole("row", { name: /partial-project/ });
  await expect(row).toContainText("0 B");
  await expect(row.getByRole("cell", { name: "未知", exact: true })).toHaveCount(4);
  await expect(page.getByText(/耗尽时间：未知/)).toBeVisible();
  expect(storageCalls(state).every((call) => call.method === "GET")).toBe(true);
});

test("unavailable initial storage data offers retry without an invented empty result", async ({ page }) => {
  const state = await fixture(page, { tab: "storage", offline: true });
  await expect(page.getByRole("alert")).toContainText("内容暂时不可用");
  await expect(page.getByRole("heading", { name: "项目与角色账目", exact: true })).toHaveCount(0);
  state.offline = false;
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await expect(page.getByRole("heading", { name: "项目与角色账目", exact: true })).toBeVisible();
});

test("a member cannot mount the admin storage dashboard", async ({ page }) => {
  const state = await fixture(page, { tab: "storage", roles: ["member"] });
  await expect(page.locator(".workspace-header")).toBeVisible();
  await expect(page.getByRole("button", { name: "存储 Storage", exact: true })).toHaveCount(0);
  expect(storageCalls(state)).toEqual([]);
});
