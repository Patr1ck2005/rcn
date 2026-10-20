import fs from "node:fs/promises";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { makeInsightsFixture } from "./insights.fixture";

const OLD_PROJECT = "Photonics / 扫描计划";
const RECENT_PROJECT = "Acoustics / 参数研究";

// Synthetic operational metadata only, with synthetic dates and identities.
// All requests and built assets are intercepted; no service or token is used.
const syntheticJob = (id, ordinal, status, projectId) => ({
  job_id: id, project_id: projectId, user_id: "fixture",
  status, activity_state: status === "running" ? "active" : "history",
  created_at: new Date(Date.UTC(2026, 9, 1) - ordinal * 1000).toISOString(),
  updated_at: "2026-10-01T09:00:00Z", revision: 1,
  unit_count: 1, completed_unit_count: status === "completed" ? 1 : 0,
  atomic_item_count: 1, completed_items: status === "completed" ? 1 : 0,
  work_units: status === "running" ? [{
    work_unit_id: `unit-${id}`, ordinal: 0, status: "running", atomic_item_count: 1, attempts: [],
  }] : [],
});

async function fixture(page) {
  const records = [
    ...Array.from({ length: 60 }, (_, index) => syntheticJob(`fixture-history-${index}`, index, "completed", RECENT_PROJECT)),
    syntheticJob("fixture-old-active", 60, "running", OLD_PROJECT),
    syntheticJob("fixture-old-history", 61, "completed", OLD_PROJECT),
  ];
  const dist = path.resolve("../src/research_compute_network/web_dist");
  const reads = [];
  let releaseHistory;
  const historyGate = new Promise((resolve) => { releaseHistory = resolve; });
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/local/v1/capabilities") return route.fulfill({ status: 404, body: "" });
    if (url.pathname.startsWith("/v1/")) {
      if (url.pathname === "/v1/events/stream") return route.abort();
      let json = [];
      if (url.pathname === "/v1/me") json = { actor_id: "fixture", roles: ["machine_owner", "member"] };
      if (url.pathname === "/v1/overview") json = { generated_at: new Date().toISOString(), machines: [], policies: {}, summary: {} };
      if (url.pathname === "/v1/settings/features") json = { visibility: "own_detail" };
      if (url.pathname === "/v1/dispatcher/status") json = { phase: "active" };
      if (url.pathname === "/v1/operations/insights") json = makeInsightsFixture(Number(url.searchParams.get("window_hours")) || 24);
      if (url.pathname === "/v1/jobs") {
        const statuses = url.searchParams.getAll("status");
        const project = url.searchParams.get("project_id");
        const offset = Number(url.searchParams.get("offset") || 0);
        const limit = Number(url.searchParams.get("limit") || 100);
        reads.push({ statuses, offset, limit, view: url.searchParams.get("view") });
        if (!statuses.length) await historyGate;
        const visible = records.filter((record) => (!statuses.length || statuses.includes(record.status)) && (!project || record.project_id === project));
        json = visible.slice(offset, offset + limit);
      }
      return route.fulfill({ json });
    }
    const name = url.pathname.startsWith("/assets/") ? url.pathname.slice(1) : "index.html";
    if (name.includes("..")) return route.abort();
    return route.fulfill({
      body: await fs.readFile(path.join(dist, name)),
      contentType: name.endsWith(".js") ? "text/javascript" : name.endsWith(".css") ? "text/css" : "text/html",
    });
  });
  return { reads, releaseHistory };
}

test("Runs reads older current work before history and retains older project records after pagination", async ({ page }) => {
  const { reads, releaseHistory } = await fixture(page);
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    await page.goto("http://rcn.fixture/app/runs");
    const records = page.locator(".data-section");
    const activeBoard = page.locator(".queue-board:not(.finished-board)");
    await expect(activeBoard.getByText("fixture-old-active", { exact: true })).toBeVisible();
    await expect(records.locator("tbody tr")).toHaveCount(1);
    await expect(records.locator(".section-heading")).toContainText("正在分页加载运行记录");
    await expect(records.locator(".section-heading")).not.toContainText("读取完成");

    releaseHistory();
    await expect(records.locator("tbody tr")).toHaveCount(51);
    await expect(records.locator(".section-heading")).toContainText("当前任务已单独读取");
    await page.getByRole("button", { name: "加载更多（50 条）", exact: true }).click();
    await expect(records.locator(".section-heading")).toContainText("62 / 62 条 · 可见 Job 分页读取完成");
    await expect(records.locator("tbody tr")).toHaveCount(62);
    expect(reads.some((read) => !read.statuses.length && read.offset === 50)).toBe(true);
    expect(reads.some((read) => ["awaiting_approval", "queued", "running", "failed_retriable"].every((status) => read.statuses.includes(status)))).toBe(true);
    expect(reads.every((read) => read.limit <= 50 && read.view === "compact")).toBe(true);

    await page.getByRole("combobox", { name: "按项目筛选" }).selectOption(OLD_PROJECT);
    await expect(page.locator(".fleet-scope-note").filter({ hasText: "当前任务列表按项目" })).toContainText(`当前任务列表按项目 ${OLD_PROJECT}`);
    await expect(records.locator("tbody tr")).toHaveCount(2);
    await expect(records.getByText("fixture-old-active", { exact: true })).toBeVisible();
    await expect(records.getByText("fixture-old-history", { exact: true })).toBeVisible();
    await expect(activeBoard.getByText("fixture-old-active", { exact: true })).toBeVisible();
    await expect(records.locator(".section-heading")).toContainText("2 / 2 条 · 可见 Job 分页读取完成");
    expect(errors).toEqual([]);
  } finally {
    releaseHistory();
  }
});
