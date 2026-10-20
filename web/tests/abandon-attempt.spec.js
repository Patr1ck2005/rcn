import fs from "node:fs/promises";
import path from "node:path";
import { expect, test } from "@playwright/test";

async function fixture(page, { admin = true, running = false, lostReply = false } = {}) {
  const dist = path.resolve(process.env.RCN_FRONTEND_TEST_DIST || "../src/research_compute_network/web_dist");
  const calls = [];
  const receiptReads = [];
  let receipt = null;
  let recoveryOffline = lostReply;
  let dropped = false;
  const job = {
    job_id: "job-original", project_id: "fixture-project", user_id: "fixture-admin", revision: 1,
    created_at: "2026-10-04T10:00:00Z", updated_at: "2026-10-12T10:00:00Z", status: "running",
    activity_state: "active", activity_phase: running ? "running" : "reconcile_pending",
    unit_count: 1, completed_unit_count: 0, atomic_item_count: 4, total_items: 4, completed_items: 0,
    reconciliation_unit_count: running ? 0 : 1, reconciliation_machine_ids: running ? [] : ["demo-node-a"],
    eta_confidence: "unknown", eta_seconds: null,
    work_units: [{ work_unit_id: "unit-original", ordinal: 0, status: running ? "running" : "reconcile_pending",
      activity_state: running ? "running" : "reconcile_pending", attempt_count: 1, max_attempts: 3,
      assigned_machine_id: "demo-node-a", total_items: 4, atomic_item_count: 4, completed_items: 0,
      attempts: [{ attempt_id: "attempt-old", state: running ? "running" : "uncertain", machine_id: "demo-node-a", external_run_id: "ssh-old", started_at: "2026-10-04T10:00:00Z" }],
    }],
  };
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/local/v1/capabilities") return route.fulfill({ status: 404, body: "" });
    if (url.pathname === "/v1/events/stream") return route.abort();
    if (url.pathname.startsWith("/v1/")) {
      if (url.pathname.endsWith("/abandon-and-retry")) {
        calls.push(route.request().postDataJSON());
        expect(route.request().method()).toBe("POST");
        expect(url.pathname).toBe("/v1/admin/jobs/job-original/units/unit-original/abandon-and-retry");
        job.status = "queued"; job.activity_state = "queued"; job.activity_phase = "queued";
        job.reconciliation_unit_count = 0; job.reconciliation_machine_ids = [];
        job.work_units[0].status = "queued"; job.work_units[0].activity_state = "queued";
        const body = route.request().postDataJSON();
        const original = job.work_units[0].attempts.find((attempt) => attempt.attempt_id === body.expected_attempt_id);
        expect(original.external_run_id).toBe(body.expected_external_run_id);
        original.state = "abandoned";
        original.abandonment = { reason: body.reason, abandoned_at: "2026-10-12T10:02:00Z" };
        const requestId = route.request().headers()["x-rcn-request-id"];
        expect(requestId).toMatch(/^[0-9a-f-]{36}$/);
        receipt = { request_id: requestId, kind: "abandon_attempt", subject_id: job.job_id, state: "completed",
          result: { operation_id: body.operation_id, job_id: job.job_id, work_unit_id: "unit-original", abandoned_attempt_id: body.expected_attempt_id, abandoned_external_run_id: body.expected_external_run_id, outcome: "queued" } };
        if (lostReply && !dropped) { dropped = true; return route.abort(); }
        // Keep the first request open across a same-frame double click.
        await new Promise((resolve) => setTimeout(resolve, 100));
        return route.fulfill({ json: receipt.result });
      }
      if (url.pathname.startsWith("/v1/metadata-operations/")) {
        receiptReads.push({ path: url.pathname, method: route.request().method() });
        if (recoveryOffline) return route.fulfill({ status: 503, json: { detail: "receipt offline" } });
        return receipt && url.pathname.endsWith(receipt.request_id) ? route.fulfill({ json: receipt })
          : route.fulfill({ status: 404, json: { detail: "unknown original operation" } });
      }
      let json = [];
      if (url.pathname === "/v1/me") json = { actor_id: "fixture-admin", roles: admin ? ["admin", "member"] : ["member"] };
      if (url.pathname === "/v1/overview") json = { generated_at: new Date().toISOString(), machines: [], policies: {}, summary: {} };
      if (url.pathname === "/v1/settings/features") json = { visibility: "full" };
      if (url.pathname === "/v1/dispatcher/status") json = { phase: "active" };
      if (url.pathname === "/v1/jobs") json = [job];
      if (url.pathname === "/v1/jobs/job-original") json = job;
      if (url.pathname === "/v1/operations/insights") return route.fulfill({ status: 503, json: { detail: "fixture omits unrelated insights" } });
      return route.fulfill({ json });
    }
    const relative = url.pathname.startsWith("/assets/") ? url.pathname.slice(1) : "index.html";
    if (relative.includes("..")) return route.abort();
    return route.fulfill({ body: await fs.readFile(path.join(dist, relative)), contentType: relative.endsWith(".js") ? "text/javascript" : relative.endsWith(".css") ? "text/css" : "text/html" });
  });
  return { calls, receiptReads, allowRecovery: () => { recoveryOffline = false; }, successor: () => {
    job.status = "running"; job.activity_state = "active"; job.activity_phase = "reconcile_pending"; job.revision += 1;
    job.reconciliation_unit_count = 1; job.reconciliation_machine_ids = ["demo-node-a"];
    Object.assign(job.work_units[0], { status: "reconcile_pending", activity_state: "reconcile_pending", attempt_count: 2, assigned_machine_id: "demo-node-a" });
    job.work_units[0].attempts.push({ attempt_id: "attempt-new", state: "uncertain", machine_id: "demo-node-a", external_run_id: "ssh-new", started_at: "2026-10-12T10:03:00Z" });
  } };
}

for (const view of ["detail", "drawer"]) {
  test(`administrator explicitly abandons only the original attempt from ${view}`, async ({ page }) => {
    const { calls } = await fixture(page);
    await page.goto(`http://rcn.fixture/app/runs${view === "detail" ? "/job-original" : "?drawer=job-original"}`);
    const container = view === "drawer" ? page.locator(".drawer") : page.locator("main.app-page");
    const action = container.getByRole("button", { name: "放弃旧尝试并重算", exact: true });
    await expect(action).toBeVisible(); expect(calls).toHaveLength(0);
    await action.click();
    const dialog = container.getByRole("dialog", { name: "放弃旧尝试并重算确认" });
    await expect(dialog).toContainText("不保证远端进程已经停止");
    await expect(dialog).toContainText("同一个单元");
    await dialog.getByLabel("放弃并重算原因").fill("手动放弃失联计算并重算");
    await dialog.getByRole("button", { name: "确认放弃并重算", exact: true }).evaluate((button) => { button.click(); button.click(); });
    await expect(container.getByRole("status").filter({ hasText: "已登记原单元重算" })).toBeVisible();
    expect(calls).toEqual([{ expected_attempt_id: "attempt-old", expected_external_run_id: "ssh-old", reason: "手动放弃失联计算并重算", operation_id: "admin-abandon-attempt-old" }]);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  });
}

test("a lost reply and reload recover the original abandonment by GET without another POST", async ({ page }) => {
  const { calls, receiptReads, allowRecovery } = await fixture(page, { lostReply: true });
  await page.goto("http://rcn.fixture/app/runs/job-original");
  await page.getByRole("button", { name: "放弃旧尝试并重算", exact: true }).click();
  await page.getByRole("button", { name: "确认放弃并重算", exact: true }).click();
  const recovery = page.getByRole("status", { name: "管理操作回执" });
  await expect(recovery).toContainText("receipt offline");
  expect(calls).toHaveLength(1);
  await page.reload(); await expect(recovery).toContainText("receipt offline");
  await expect(page.getByRole("button", { name: "确认放弃并重算", exact: true })).toHaveCount(0);
  allowRecovery(); await recovery.getByRole("button", { name: "核对原操作", exact: true }).click();
  await expect(recovery).toContainText("放弃旧尝试并重算已完成");
  expect(calls).toHaveLength(1);
  expect(receiptReads.length).toBeGreaterThanOrEqual(3);
  expect(receiptReads.every((call) => call.method === "GET" && call.path === receiptReads[0].path)).toBe(true);
});

test("ordinary members have no administrator abandonment action", async ({ page }) => {
  const { calls } = await fixture(page, { admin: false });
  await page.goto("http://rcn.fixture/app/runs/job-original");
  await expect(page.getByRole("heading", { name: "job-original", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "放弃旧尝试并重算", exact: true })).toHaveCount(0);
  expect(calls).toHaveLength(0);
});

test("known running computation is never automatically abandoned", async ({ page }) => {
  const { calls } = await fixture(page, { running: true });
  await page.goto("http://rcn.fixture/app/runs/job-original");
  await expect(page.getByRole("heading", { name: "job-original", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "放弃旧尝试并重算", exact: true })).toHaveCount(0);
  expect(calls).toHaveLength(0);
});

for (const lostReply of [false, true]) {
  test(`a successor keeps its own recovery action after ${lostReply ? "a late original receipt" : "an original completion"}`, async ({ page }) => {
    const { calls, successor, allowRecovery } = await fixture(page, { lostReply });
    await page.goto("http://rcn.fixture/app/runs/job-original");
    await page.getByRole("button", { name: "放弃旧尝试并重算", exact: true }).click();
    await page.getByRole("button", { name: "确认放弃并重算", exact: true }).click();
    const recovery = page.getByRole("status", { name: "管理操作回执" });
    if (lostReply) await expect(recovery).toContainText("receipt offline");
    else await expect(page.getByRole("status").filter({ hasText: "已登记原单元重算" })).toBeVisible();
    successor(); await page.locator('.workspace-header button[title="刷新"]').click();
    if (lostReply) {
      allowRecovery(); await recovery.getByRole("button", { name: "核对原操作", exact: true }).click();
      await expect(recovery).toContainText("放弃旧尝试并重算已完成");
    }
    const action = page.getByRole("button", { name: "放弃旧尝试并重算", exact: true });
    await expect(action).toBeVisible();
    await expect(page.getByRole("status").filter({ hasText: "已登记原单元重算" })).toHaveCount(0);
    await action.click(); await expect(page.getByRole("dialog", { name: "放弃旧尝试并重算确认" })).toContainText("attempt-new");
    await page.getByRole("button", { name: "确认放弃并重算", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "已登记原单元重算" })).toBeVisible();
    expect(calls).toHaveLength(2);
    expect(calls[0].expected_attempt_id).toBe("attempt-old"); expect(calls[1].expected_attempt_id).toBe("attempt-new");
    expect(calls[1].expected_external_run_id).toBe("ssh-new");
    expect(calls[1].operation_id).not.toBe(calls[0].operation_id);
  });
}
