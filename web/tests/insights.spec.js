import fs from "node:fs";
import path from "node:path";
import { test, expect } from "@playwright/test";
import { makeInsightsFixture } from "./insights.fixture";

const fixtureFile = process.env.RCN_INSIGHT_FIXTURES;
const shots = process.env.RCN_SCREENSHOT_DIR;
async function wire(page, { stale = false, empty = false } = {}) {
  const fixtures = fixtureFile ? JSON.parse(fs.readFileSync(fixtureFile, "utf8")) : null;
  await page.route("**/v1/operations/insights?*", async r => {
    const hours = new URL(r.request().url()).searchParams.get("window_hours");
    const data = fixtures ? structuredClone(fixtures[hours]) : makeInsightsFixture(Number(hours));
    data.dataset_mode = "demo";
    data.generated_at = stale ? "2000-01-01T00:00:00Z" : new Date().toISOString();
    if (empty) { data.projects = []; data.job_forecasts = {}; data.project_count = 0; }
    await r.fulfill({ json: data });
  });
  await page.route("**/v1/jobs?*", async r => {
    const response = await r.fetch();
    const rows = await response.json();
    if (rows.length) {
      const first = rows[0];
      await r.fulfill({ json: [
        { ...first, job_id: "fixture-alpha-job", project_id: "Photonics / 扫描计划", user_id: "demo" },
        { ...first, job_id: "fixture-beta-job", project_id: "Acoustics / 参数研究", user_id: "demo" },
      ] });
    } else await r.fulfill({ json: rows });
  });
}
test.afterEach(async ({ page }) => { await page.unrouteAll({ behavior: "ignoreErrors" }); });

async function noOverflow(page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
}

test("cluster overview charts, project and time-window filters", async ({ page }, testInfo) => {
  await wire(page);
  const errors=[];page.on("pageerror", e => errors.push(e.message));
  await page.goto("/app/overview");
  await expect(page.getByRole("heading", { name: "全网运行总览", exact: true })).toBeVisible();
  await expect(page.locator(".insight-stat")).toHaveCount(4);
  await expect(page.getByRole("heading", { name: "产出趋势", exact: true })).toBeVisible();
  await expect(page.locator(".insight-chart svg").first()).toBeVisible();
  await noOverflow(page);
  if (shots) await page.screenshot({ path: path.join(shots, `overview-${testInfo.project.name}.png`), fullPage: true });
  await page.locator(".insight-chart-grid.secondary .recharts-bar-rectangle path").first().click();
  await expect(page.getByRole("combobox", { name: "按项目筛选" })).not.toHaveValue("");
  await page.getByRole("combobox", { name: "按项目筛选" }).selectOption("Photonics / 扫描计划");
  await expect(page.getByRole("heading", { name: "Photonics / 扫描计划", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "6 小时", exact: true }).click();
  await expect(page.getByRole("button", { name: "6 小时", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator(".insight-footnote")).toContainText("快照");
  await page.getByRole("textbox", { name: "搜索效能项目" }).fill("Photonics");
  await expect(page.locator(".insight-project-table tbody tr")).toHaveCount(1);
  await expect(page.locator(".insight-project-table tbody a")).toHaveAttribute("href", /project=Photonics/);
  await noOverflow(page);
  await page.goto("/app/help/cluster-insights");
  await expect(page.getByRole("heading", { name: "如何阅读集群效能总览", exact: true })).toBeVisible();
  await expect(page.locator(".help-article article")).toContainText("有效执行占比");
  expect(errors).toEqual([]);
});

test("Fleet and Runs retain controls and expose the same summary", async ({ page }) => {
  await wire(page);
  await page.goto("/app/fleet");
  await expect(page.getByRole("heading", { name: "集群工作摘要" })).toBeVisible();
  await expect(page.locator(".fleet-table")).toBeVisible();
  await noOverflow(page);
  await page.goto("/app/runs?project=Photonics%20%2F%20%E6%89%AB%E6%8F%8F%E8%AE%A1%E5%88%92");
  await expect(page.getByRole("combobox", { name: "按项目筛选" })).toHaveValue("Photonics / 扫描计划");
  await expect(page.locator(".fleet-scope-note")).toContainText("当前任务列表按项目");
  await expect(page.locator(".queue-board")).not.toContainText("fixture-beta-job");
  await noOverflow(page);
});

test("stale data is visible, not a zero ETA or hidden failure", async ({ page }) => {
  await wire(page, { stale: true });
  await page.goto("/app/overview");
  await expect(page.locator(".insight-warning")).toContainText("过期");
  await expect(page.locator(".insight-stat").last()).toContainText("待刷新");
  await page.locator(".insight-footnote summary").click();
  await expect(page.locator(".insight-footnote details")).toContainText("不是CPU使用率");
  await noOverflow(page);
});

test("insights request failure does not remove the machine workspace", async ({ page }) => {
  await wire(page);
  await page.route("**/v1/operations/insights?*", r => r.fulfill({ status: 503, json: { detail: "fixture unavailable" } }));
  await page.goto("/app/fleet");
  await expect(page.locator(".insights-panel")).toContainText("内容暂时不可用");
  await expect(page.locator(".fleet-table")).toBeVisible();
  await noOverflow(page);
});


test("dark theme and enlarged text remain legible without page overflow", async ({ page }, testInfo) => {
  await wire(page);
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await page.goto("/app/overview");
  await expect(page.locator(".insight-stat")).toHaveCount(4);
  await expect(page.locator(".insight-chart svg").first()).toBeVisible();
  await noOverflow(page);
  if (shots) await page.screenshot({ path: path.join(shots, `overview-dark-${testInfo.project.name}.png`), fullPage: true });
  await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
  await noOverflow(page);
  await expect(page.getByRole("combobox", { name: "按项目筛选" })).toBeVisible();
});
