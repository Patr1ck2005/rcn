import { expect, test } from "@playwright/test";

async function fixture(page, admin = false) {
  const original = await (await page.request.get("/v1/overview")).json();
  const [old, current] = original.machines;
  old.record_state = "revoked_history";
  current.record_state = "current";
  old.owner_user_id = current.owner_user_id = "member-test";
  original.machines = [old, current];
  original.fleet_summary = { ...original.summary, total_machines: 1, historical_machines: 1, online_machines: 1, offline_machines: 0, alert_count: 0 };
  await page.route("**/v1/overview", (route) => route.fulfill({ json: original }));
  await page.route("**/v1/events/stream", (route) => route.abort());
  await page.route("**/v1/me", (route) => route.fulfill({ json: { actor_id: "member-test", roles: admin ? ["admin", "machine_owner"] : ["member", "machine_owner"] } }));
  await page.route("**/v1/settings/features", async (route) => {
    const response = await route.fetch();
    await route.fulfill({ json: { ...await response.json(), visibility: "own_detail" } });
  });
  return { old: old.machine_id, current: current.machine_id };
}

test("member Fleet folds history, searches both sections and counts current only", async ({ page }) => {
  const ids = await fixture(page);
  await page.goto("/app/fleet");
  await expect(page.getByText(/仅显示你拥有的机器/)).toBeVisible();
  await expect(page.locator(".fleet-group-summary")).toContainText("不包含其他成员详情");
  await expect(page.locator(".fleet-table tbody tr")).toHaveCount(1);
  await expect(page.getByText("1 / 1", { exact: true })).toBeVisible();
  const history = page.locator(".fleet-history");
  await expect(history.locator("summary")).toHaveText("历史记录（1）");
  await expect(history).not.toHaveAttribute("open", "");
  await history.locator("summary").click();
  await expect(history.getByText("已撤销 · 历史")).toBeVisible();
  await expect(history.locator('input,select')).toHaveCount(0);
  await expect(history.getByRole("link", { name: "查看审计" })).toHaveAttribute("href", `/app/machines/${ids.old}?tab=events`);
  await page.getByPlaceholder("搜索机器、所有者或能力").fill(ids.old);
  await expect(page.locator(".fleet-table tbody tr")).toHaveCount(0);
  await expect(history.locator("article")).toHaveCount(1);
  await expect(page.getByText("1 / 1", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});

test("old selections and administrator history detail remain read-only", async ({ page }) => {
  const ids = await fixture(page, true);
  await page.goto(`/app/fleet?selected=${ids.old},${ids.current}`);
  await expect(page.locator(".batch-bar b")).toHaveText("已选择 1 台");
  await expect(page.locator(".batch-bar")).not.toContainText(ids.old);
  await page.goto(`/app/machines/${ids.old}?tab=control`);
  await expect(page.getByText(/已撤销 · 历史记录：仅供查看/)).toBeVisible();
  await expect(page.getByRole("button", { name: "开放", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "查看配置", exact: true }).click();
  await expect(page.locator(".machine-detail-page input:not([disabled]), .machine-detail-page select:not([disabled])")).toHaveCount(0);
});
