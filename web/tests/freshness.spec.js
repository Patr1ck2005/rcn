import fs from "node:fs/promises";
import path from "node:path";
import { expect, test } from "@playwright/test";

// Fully intercepted fixture: no production server, token, or test service.
async function fixture(page, machines = []) {
  const state = { generation: 1, reads: 0 };
  const dist = path.resolve("../src/research_compute_network/web_dist");
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/local/v1/capabilities") return route.fulfill({ status: 404, body: "" });
    if (url.pathname.startsWith("/v1/")) {
      if (url.pathname === "/v1/events/stream") return route.abort();
      let json = [];
      if (url.pathname === "/v1/me") json = { actor_id: "fixture", roles: ["machine_owner", "member"] };
      if (url.pathname === "/v1/overview") json = { generated_at: new Date().toISOString(), machines, policies: {}, summary: {} };
      if (url.pathname === "/v1/settings/features") json = { visibility: "own_detail" };
      if (url.pathname === "/v1/dispatcher/status") json = { phase: "active" };
      if (url.pathname === "/v1/jobs" && machines.length) json = [{
        job_id: "fixture-active-job", project_id: "fixture", user_id: "fixture",
        activity_state: "queued", status: "queued", work_units: [],
      }];
      if (url.pathname === "/v1/projects") {
        state.reads++;
        json = [{ project_id: `fresh-${state.generation}`, owner_user_id: "fixture", trusted_user_ids: [], allowed_execution_profiles: [] }];
      }
      if (url.pathname === "/v1/machines/fixture/detail") json = {
        machine: { machine_id: "fixture", owner_user_id: "fixture", display_name: `machine-${state.generation}`, total_cpus: 8, total_memory_mb: 8192, total_gpus: 0 },
        policy: { owner_mode: "paused", max_concurrent_units: 1 }, execution_config: { max_concurrent_units: 1 },
        operational_status: { supervisor_state: "online", telemetry_state: "live" }, events: [], jobs: [],
      };
      return route.fulfill({ json });
    }
    const name = url.pathname.startsWith("/assets/") ? url.pathname.slice(1) : "index.html";
    if (name.includes("..")) return route.abort();
    return route.fulfill({ body: await fs.readFile(path.join(dist, name)), contentType: name.endsWith(".js") ? "text/javascript" : name.endsWith(".css") ? "text/css" : "text/html" });
  });
  return state;
}

test("return to a tab refreshes page-owned data and preserves registration draft", async ({ page }) => {
  const state = await fixture(page);
  const errors = []; page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("http://rcn.fixture/app/projects");
  await expect(page.getByText("fresh-1", { exact: true })).toBeVisible();
  const input = page.getByLabel("项目 ID", { exact: true });
  await input.fill("keep-my-draft");
  state.generation = 2;
  await page.evaluate(() => {
    document.dispatchEvent(new Event("visibilitychange"));
    window.dispatchEvent(new Event("focus")); window.dispatchEvent(new Event("online"));
  });
  await expect(page.getByText("fresh-2", { exact: true })).toBeVisible();
  await expect(input).toHaveValue("keep-my-draft");
  expect(errors).toEqual([]);
});

test("Runs folds revoked machine identities without hiding ordinary offline lanes", async ({ page }) => {
  await fixture(page, [
    { machine_id: "retired-test", owner_user_id: "fixture", record_state: "revoked_history" },
    { machine_id: "ordinary-offline", owner_user_id: "fixture", record_state: "current" },
    { machine_id: "legacy-paused", owner_user_id: "fixture" },
  ]);
  const errors = []; page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("http://rcn.fixture/app/runs");
  await expect(page.locator(".machine-lane").filter({ hasText: "ordinary-offline" })).toBeVisible();
  await expect(page.locator(".machine-lane").filter({ hasText: "legacy-paused" })).toBeVisible();
  await expect(page.locator(".machine-lane").filter({ hasText: "retired-test" })).toHaveCount(0);
  const history = page.locator(".lane-board .fleet-history");
  await expect(history.locator("summary")).toHaveText("历史记录（1）");
  await expect(history).not.toHaveAttribute("open", "");
  await expect(history.getByRole("link", { name: "查看详情" })).not.toBeVisible();
  await history.locator("summary").click();
  await expect(history.getByText("已撤销 · 历史", { exact: true })).toBeVisible();
  await expect(history.getByRole("link", { name: "查看详情" })).toHaveAttribute("href", "/app/machines/retired-test");
  await expect(history.getByRole("link", { name: "查看审计" })).toHaveAttribute("href", "/app/machines/retired-test?tab=events");
  await expect(history.getByRole("button")).toHaveCount(0);
  expect(errors).toEqual([]);
});

test("global refresh updates machine detail without resetting policy edits", async ({ page }) => {
  const state = await fixture(page);
  const errors = []; page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("http://rcn.fixture/app/machines/fixture?tab=config");
  await expect(page.getByRole("heading", { name: "machine-1", exact: true })).toBeVisible();
  const owner = page.getByLabel("所有者模式", { exact: true });
  await owner.selectOption("drain");
  state.generation = 2;
  await page.locator('.workspace-header button[title="刷新"]').click();
  await expect(page.getByRole("heading", { name: "machine-2", exact: true })).toBeVisible();
  await expect(owner).toHaveValue("drain");
  expect(errors).toEqual([]);
});
