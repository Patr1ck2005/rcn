import { build } from "esbuild";
import { expect, test } from "@playwright/test";
import { memberApiFixture, selectTaskPackage } from "./member-client.fixture";
import { makeInsightsFixture } from "./insights.fixture";

// Bundle current source into memory; never serve stale production assets.
let bundle;
test.beforeAll(async () => {
  const result = await build({ entryPoints: ["src/main.jsx"], bundle: true, write: false, outdir: "ignored-in-memory",
    jsx: "automatic", define: { "process.env.NODE_ENV": '"production"' } });
  bundle = result.outputFiles;
});

const makeJob = (id, status = "completed", ordinal = 0) => ({
  job_id: id, project_id: "fixture-project", user_id: "fixture", status,
  activity_state: status === "running" ? "active" : "history", activity_phase: status === "running" ? "running" : "completed",
  created_at: new Date(Date.UTC(2026, 9, 1) - ordinal * 1000).toISOString(), updated_at: "2026-10-17T12:00:00Z", revision: 1,
  unit_count: 1, completed_unit_count: status === "completed" ? 1 : 0, atomic_item_count: 1, completed_items: status === "completed" ? 1 : 0,
  work_units: [{ work_unit_id: `unit-${id}`, ordinal: 0, status, atomic_item_count: 1, attempts: [] }],
});

async function installLiveStream(page) {
  await page.addInitScript(() => {
    sessionStorage.removeItem("rcn-last-event-sequence");
    const nativeFetch = window.fetch.bind(window);
    window.fetch = (input, options) => {
      if (!String(input).includes("/v1/events/stream")) return nativeFetch(input, options);
      const encoder = new TextEncoder();
      const body = new ReadableStream({ start(controller) {
        const write = (type, value) => controller.enqueue(encoder.encode(`event: ${type}\ndata: ${JSON.stringify(value)}\n\n`));
        window.__rcnEmitState = (value) => write("state", value);
        write("connected", { latest_sequence: 0 });
        options?.signal?.addEventListener("abort", () => { try { controller.error(new DOMException("Aborted", "AbortError")); } catch {} }, { once: true });
      } });
      return Promise.resolve(new Response(body, { headers: { "Content-Type": "text/event-stream" } }));
    };
  });
}

async function boot(page, initialPath, configure = () => {}) {
  const state = { calls: [], history: [...Array.from({ length: 60 }, (_, index) => makeJob(`history-${index}`, "completed", index)), makeJob("old-active", "running", 61)],
    runs: [], failRuns: false, failManifests: false, dropConfirm: false, dispatcher: { phase: "stopped", process: { running: false, control_mode: "open" } },
    job: makeJob("detail-job", "running"), policy: null };
  configure(state);
  await page.route("**/*", async (route) => {
    const request = route.request(), url = new URL(request.url());
    state.calls.push({ path: url.pathname, query: url.search, method: request.method(), body: request.postData() });
    if (url.pathname === "/bundle.js") return route.fulfill({ contentType: "application/javascript", body: bundle.find((file) => file.path.endsWith(".js")).text });
    if (url.pathname === "/bundle.css") return route.fulfill({ contentType: "text/css", body: bundle.find((file) => file.path.endsWith(".css")).text });
    if (state.member && url.pathname.startsWith("/local/v1/")) return route.fallback();
    if (url.pathname === "/local/v1/capabilities") return route.fulfill({ status: 404, body: "" });
    if (url.pathname === "/v1/events/stream") {
      if (state.streamResponse) {
        const response = state.streamResponse; state.streamResponse = null;
        return route.fulfill({ contentType: "text/event-stream", body: await response });
      }
      return route.abort();
    }
    const json = (data, status = 200) => route.fulfill({ status, json: data });
    if (url.pathname === "/v1/me") return json(state.me || { actor_id: "fixture", roles: ["admin", "member"] });
    if (url.pathname === "/v1/overview") return json(state.overview || { generated_at: new Date().toISOString(), machines: [], policies: {}, summary: {} });
    if (url.pathname === "/v1/settings/features") return json({ visibility: "full" });
    if (url.pathname === "/v1/dispatcher/status") return json(state.dispatcher);
    if (url.pathname === "/v1/settings/scheduling" && state.scheduling) return json(state.scheduling);
    if (url.pathname === "/v1/operations/insights" && state.insights) return json(await state.insights());
    if (url.pathname === "/v1/operations/insights" || url.pathname === "/v1/settings/scheduling") return json({ detail: "fixture omits unrelated data" }, 503);
    if (url.pathname === "/v1/release/identity") return json({ build: {}, package_version: "fixture" });
    if (url.pathname === "/v1/jobs") {
      const statuses = url.searchParams.getAll("status");
      const records = state.history.filter((job) => !statuses.length || statuses.includes(job.status));
      const offset = Number(url.searchParams.get("offset") || 0), limit = Number(url.searchParams.get("limit") || 100);
      return json(records.slice(offset, offset + limit));
    }
    if (url.pathname === "/v1/jobs/detail-job") return json(state.job);
    if (url.pathname === "/v1/jobs/detail-job/artifact-manifests") return state.failManifests ? json({ detail: "manifest transport failed" }, 503)
      : json([{ work_unit_id: "unit-detail-job", files: [{ relative_path: "retained-result.json", size_bytes: 12, sha256: "a".repeat(64) }] }]);
    if (url.pathname === "/v1/admin/control-runs") return state.failRuns ? json({ detail: "runs temporarily unavailable" }, 503) : json(state.runs);
    if (url.pathname === "/v1/admin/dispatcher-controls/preview") {
      state.previewCount = (state.previewCount || 0) + 1;
      return json({ ticket_id: state.rotateTicket && state.previewCount > 1 ? "ticket-revised" : "ticket-original", confirmation_hash: "original-hash", action: "start", expires_at: "2026-10-18T12:00:00Z" });
    }
    if (url.pathname === "/v1/admin/dispatcher-controls/confirm") {
      if (state.rejectConfirm) { state.rejectConfirm = false; return json({ detail: "ticket needs a fresh preview" }, 409); }
      state.runs = [{ operation_id: "operation-original", ticket_id: request.postDataJSON().ticket_id, state: "accepted", action: "start", targets: [], requested_by: "fixture" }];
      if (state.dropConfirm) { state.dropConfirm = false; return route.abort(); }
      return json(state.runs[0]);
    }
    if (url.pathname === "/v1/admin/control-runs/by-ticket/ticket-original") return state.recoveryOffline ? json({ detail: "recovery read unavailable" }, 503) : state.runs.length ? json(state.runs[0]) : json({ detail: "not accepted" }, 404);
    if (url.pathname === "/v1/me/submission-policy") return json({ policy: state.policy, usage: { queued_units: 0, running_units: 0 } });
    if (url.pathname === "/v1/me/compute-credits") return json({ available_cpu_core_hours: 12, available_gpu_device_hours: 2, reserved_cpu_core_hours: 1, reserved_gpu_device_hours: 0, settings: { metering_enabled: false } });
    if (url.pathname === "/v1/users") return json([{ user_id: "member-a", display_name: "Member A", active: true, roles: ["member"] }]);
    if (url.pathname === "/v1/profiles") return json([{ profile_id: "fixed-profile" }]);
    if (url.pathname === "/v1/admin/people/member-a/submission-policy") {
      if (request.method() === "PUT") { state.policy = request.postDataJSON(); return json(state.policy); }
      return json({ person_id: "member-a", policy: state.policy, usage: {} });
    }
    if (state.respond && await state.respond({ route, request, url, json })) return;
    if (url.pathname.startsWith("/v1/")) return json([]);
    return route.fulfill({ contentType: "text/html", body: '<html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/bundle.css"><div id="root"></div><script src="/bundle.js"></script></html>' });
  });
  await page.goto(`http://rcn-ui.test${initialPath}`);
  return state;
}

test("route reads stay bounded and Runs loads older current work plus explicit history pages", async ({ page }) => {
  const state = await boot(page, "/app/overview");
  await expect(page.locator(".workspace-header")).toBeVisible();
  await page.locator('.workspace-header button[title="刷新"]').click();
  expect(state.calls.filter((call) => call.path === "/v1/jobs")).toHaveLength(0);
  if (!await page.locator('a[href="/app/runs"]').first().isVisible()) await page.locator(".nav-toggle").click();
  await page.locator('a[href="/app/runs"]').first().click();
  await expect(page.locator(".queue-board:not(.finished-board)").getByText("old-active", { exact: true })).toBeVisible();
  await expect(page.locator(".data-section tbody tr")).toHaveCount(51);
  await page.getByRole("button", { name: "加载更多（50 条）", exact: true }).click();
  await expect(page.locator(".data-section tbody tr")).toHaveCount(61);
  await expect(page.locator(".data-section .section-heading")).toContainText("分页读取完成");
  expect(state.calls.filter((call) => call.path === "/v1/jobs").every((call) => Number(new URLSearchParams(call.query).get("limit")) <= 50)).toBe(true);
});

test("stable finished-card callbacks keep pin, drawer, dismissal and project selection bound to the clicked Job", async ({ page }) => {
  await boot(page, "/app/runs", (state) => {
    state.history = [makeJob("finished-a"), makeJob("finished-b", "completed", 1)];
    state.insights = () => {
      const data = makeInsightsFixture();
      data.projects[0].project_id = "fixture-project";
      return data;
    };
  });
  const cards = page.locator(".finished-board .finished-job");
  await expect(cards).toHaveCount(2);
  const first = page.locator('.finished-job[data-job-id="finished-a"]');
  const second = page.locator('.finished-job[data-job-id="finished-b"]');
  await first.click();
  await expect(first).toHaveClass(/pinned/);
  await second.click();
  await expect(second).toHaveClass(/pinned/);
  await expect(first).not.toHaveClass(/pinned/);
  await second.getByRole("button", { name: "详情抽屉", exact: true }).click();
  await expect(page.locator(".drawer").getByRole("heading", { name: "finished-b", exact: true })).toBeVisible();
  await page.locator('.drawer > header button[title="关闭"]').click();
  await first.click();
  await first.getByRole("button", { name: "关闭", exact: true }).click();
  await expect(first).toHaveCount(0);
  await expect(second).toBeVisible();
  await page.getByLabel("按项目筛选", { exact: true }).selectOption("fixture-project");
  await expect(page).toHaveURL(/project=fixture-project/);
  await expect(cards).toHaveCount(1);
  await expect(page.locator(".data-section tbody tr")).toHaveCount(2);
});

test("initial SSE baseline and initial pageshow share one snapshot on each navigation", async ({ page }) => {
  await installLiveStream(page);
  const state = await boot(page, "/app/overview");
  const paths = ["/v1/me", "/v1/settings/features", "/v1/operations/insights"];
  for (const navigation of [1, 2]) {
    if (navigation === 2) await page.reload();
    await expect(page.locator(".workspace-header")).toBeVisible();
    await expect(page.getByText("事件连接正常", { exact: true })).toBeVisible();
    await expect.poll(() => state.calls.filter((call) => call.path === "/v1/operations/insights").length).toBe(navigation);
    await page.evaluate(() => dispatchEvent(new PageTransitionEvent("pageshow", { persisted: false })));
    await page.waitForTimeout(400);
    for (const path of paths) expect(state.calls.filter((call) => call.path === path), path).toHaveLength(navigation);
    expect(state.calls.filter((call) => call.path === "/v1/overview")).toHaveLength(0);
  }
});

test("live Job bursts refresh Overview insights once without reading Fleet, identity or settings", async ({ page }) => {
  await installLiveStream(page);
  const state = await boot(page, "/app/overview");
  await expect(page.getByText("事件连接正常", { exact: true })).toBeVisible();
  await expect.poll(() => state.calls.filter((call) => call.path === "/v1/operations/insights").length).toBe(1);
  await page.evaluate(() => {
    for (let sequence = 1; sequence <= 10; sequence += 1) window.__rcnEmitState({ sequence, event_id: `job-event-${sequence}`, event_type: "job.updated", subject_type: "job", subject_id: "fixture-job" });
  });
  await expect.poll(() => state.calls.filter((call) => call.path === "/v1/operations/insights").length).toBe(2);
  await page.waitForTimeout(350);
  for (const path of ["/v1/me", "/v1/settings/features"]) expect(state.calls.filter((call) => call.path === path)).toHaveLength(1);
  expect(state.calls.filter((call) => call.path === "/v1/overview")).toHaveLength(0);
  expect(state.calls.filter((call) => call.path === "/v1/jobs")).toHaveLength(0);
});

test("a late SSE handshake still revalidates after the bounded initial fallback", async ({ page }) => {
  let release;
  const stream = new Promise((resolve) => { release = resolve; });
  const state = await boot(page, "/app/overview", (value) => { value.streamResponse = stream; });
  await expect(page.locator(".workspace-header")).toBeVisible();
  await expect.poll(() => state.calls.filter((call) => call.path === "/v1/operations/insights").length).toBe(1);
  release('event: connected\ndata: {"latest_sequence":0}\n\n');
  await expect.poll(() => state.calls.filter((call) => call.path === "/v1/operations/insights").length).toBe(2);
  expect(state.calls.filter((call) => call.path === "/v1/overview")).toHaveLength(0);
});

test("Overview reads only Insights snapshot time while Runs retains Fleet lanes", async ({ page }) => {
  await installLiveStream(page);
  const snapshot = makeInsightsFixture();
  snapshot.generated_at = new Date(Date.now() - 17000).toISOString();
  snapshot.read_state = { stale: true, refreshing: false, age_seconds: 17,
    last_success_at: snapshot.generated_at, refresh_error: "RuntimeError" };
  const state = await boot(page, "/app/overview", (value) => {
    value.insights = () => snapshot;
    value.overview = { generated_at: "2026-10-17T12:00:00Z", policies: {}, summary: {},
      machines: [{ machine_id: "fixture-worker", display_name: "Fixture Fleet worker", metrics: { running_units: 1 } }],
      operational_statuses: { "fixture-worker": { heartbeat_phase: "healthy" } } };
    value.history.find((job) => job.job_id === "old-active").work_units[0].assigned_machine_id = "fixture-worker";
  });
  await expect(page.locator(".insight-stat")).toHaveCount(4);
  await expect(page.locator(".insight-footnote time")).toHaveAttribute("datetime", snapshot.generated_at);
  await expect(page.locator(".insight-warning")).toContainText("后台更新失败");
  await expect(page.locator(".workspace-header")).toContainText("统计快照时间见下方");
  await expect(page.locator(".workspace-header")).not.toContainText("总览更新");
  const fleetReads = () => state.calls.filter((call) => call.method === "GET" && call.path === "/v1/overview");
  expect(fleetReads()).toHaveLength(0);
  expect(state.calls.filter((call) => call.method === "GET" && call.path === "/v1/operations/insights")
    .map((call) => call.path + call.query)).toEqual(["/v1/operations/insights?window_hours=24"]);
  await page.locator('.workspace-header button[title="刷新"]').click();
  await expect.poll(() => state.calls.filter((call) => call.path === "/v1/operations/insights").length).toBe(2);
  expect(fleetReads()).toHaveLength(0);
  await expect(page.locator(".insight-footnote time")).toHaveAttribute("datetime", snapshot.generated_at);
  if (!await page.locator('a[href="/app/runs"]').first().isVisible()) await page.locator(".nav-toggle").click();
  await page.locator('a[href="/app/runs"]').first().click();
  await expect(page.locator(".machine-lane").getByText("Fixture Fleet worker", { exact: true })).toBeVisible();
  await expect(page.locator(".workspace-header")).toContainText("总览更新");
  await expect(page.locator(".workspace-header")).not.toContainText("统计快照时间见下方");
  expect(fleetReads().map((call) => call.path + call.query)).toEqual(["/v1/overview"]);
  await expect(page.locator(".machine-lane").getByText("实时", { exact: true })).toBeVisible();
});

test("Admin nodes keeps enrollment history and private invitations without legacy issuance", async ({ page }) => {
  const state = await boot(page, "/app/admin?tab=nodes", (value) => {
    value.respond = async ({ url, json }) => {
      if (url.pathname !== "/v1/admin/enrollments") return false;
      await json([{ enrollment_id: "old-enrollment", owner_user_id: "historical-owner", machine_id: "old-machine", used_at: "2026-10-01T00:00:00Z" }]);
      return true;
    };
  });
  await expect(page.getByRole("heading", { name: "历史节点登记", exact: true })).toBeVisible();
  await expect(page.getByText("historical-owner", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "邀请新成员", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "节点准入与运行时", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "签发准入码", exact: true })).toHaveCount(0);
  expect(state.calls.filter((call) => call.path === "/v1/admin/enrollments" && call.method === "POST")).toHaveLength(0);
});

test("ControlCenter retains independent sources and recovers one confirmation after a lost response", async ({ page }) => {
  const state = await boot(page, "/app/control", (value) => { value.dropConfirm = true; });
  await expect(page.getByRole("heading", { name: "控制中心", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "启动", exact: true })).toBeEnabled();
  await page.getByRole("button", { name: "启动", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Dispatcher start" });
  await dialog.getByRole("button", { name: "生成预览", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(dialog).toContainText("ticket-original");
  await dialog.getByRole("button", { name: "确认执行", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText("operation-original", { exact: true })).toBeVisible();
  expect(state.calls.filter((call) => call.path.endsWith("dispatcher-controls/preview"))).toHaveLength(1);
  expect(state.calls.filter((call) => call.path.endsWith("dispatcher-controls/confirm"))).toHaveLength(1);
  expect(state.calls.some((call) => call.path.includes("by-ticket/ticket-original"))).toBe(true);
  state.failRuns = true;
  state.dispatcher.process = { running: true, control_mode: "drain", accepting_assignments: false };
  await page.locator("main.app-page").getByRole("button", { name: "刷新", exact: true }).click();
  await expect(page.locator(".dispatcher-state")).toContainText("运行中 · 排空");
  await expect(page.getByText("operation-original", { exact: true })).toBeVisible();
  await expect(page.locator(".inline-error").filter({ hasText: "runs temporarily unavailable" })).toBeVisible();
});

test("JobDetail keeps manifests after their refresh fails while operational state advances", async ({ page }) => {
  const state = await boot(page, "/app/runs/detail-job");
  await expect(page.getByText("retained-result.json", { exact: true })).toBeVisible();
  state.failManifests = true; state.job = { ...state.job, status: "completed", activity_state: "history", activity_phase: "completed", revision: 2 };
  await page.locator('.workspace-header button[title="刷新"]').click();
  await expect(page.locator(".detail-title")).toContainText("完成");
  await expect(page.getByText("retained-result.json", { exact: true })).toBeVisible();
  await expect(page.getByText(/manifest transport failed/)).toBeVisible();
  expect(state.calls.filter((call) => call.path === "/v1/jobs/detail-job" && new URLSearchParams(call.query).get("view") === "full")).toHaveLength(1);
});

test("late control detail response cannot replace a newly selected operation", async ({ page }) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const state = await boot(page, "/app/control/operation-a", (value) => {
    value.respond = async ({ url, json }) => {
      const match = url.pathname.match(/^\/v1\/admin\/control-runs\/(operation-[ab])$/);
      if (!match) return false;
      if (match[1] === "operation-a") await gate;
      await json({ operation_id: match[1], ticket_id: `ticket-${match[1]}`, state: "completed", action: match[1], targets: [] });
      return true;
    };
  });
  try {
    await expect.poll(() => state.calls.some((call) => call.path.endsWith("control-runs/operation-a"))).toBe(true);
    await page.evaluate(() => { history.pushState({}, "", "/app/control/operation-b"); dispatchEvent(new PopStateEvent("popstate")); });
    await expect(page.locator(".detail-grid")).toContainText("ticket-operation-b");
    release();
    await expect(page.locator(".detail-grid")).not.toContainText("ticket-operation-a");
  } finally { release(); }
});

test("administrator saves one person policy and member sees balance and pool labels", async ({ page }) => {
  const state = await boot(page, "/app/admin");
  await expect(page.getByRole("heading", { name: "个人提交权限", exact: true })).toBeVisible();
  await page.getByLabel("开通提交", { exact: true }).check();
  await page.getByRole("listbox", { name: "个人允许的 Profile", exact: true }).selectOption("fixed-profile");
  await page.getByRole("button", { name: "保存个人提交权限", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(page.getByText("个人提交权限已保存，适用该成员的全部项目。", { exact: true })).toBeVisible();
  expect(state.calls.filter((call) => call.path === "/v1/admin/people/member-a/submission-policy" && call.method === "PUT")).toHaveLength(1);
  if (!await page.locator('a[href="/app/projects"]').first().isVisible()) await page.locator(".nav-toggle").click();
  await page.locator('a[href="/app/projects"]').first().click();
  await expect(page.getByRole("heading", { name: "我的计算额度", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "互助池", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "免费空闲池", exact: true })).toBeVisible();
});

test("an ambiguous confirm keeps its ticket and recovers by a read without another write", async ({ page }) => {
  const state = await boot(page, "/app/control", (value) => { value.dropConfirm = true; value.recoveryOffline = true; });
  await page.getByRole("button", { name: "启动", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Dispatcher start" });
  await dialog.getByRole("textbox").fill("keep this draft reason");
  await dialog.getByRole("button", { name: "生成预览", exact: true }).click();
  await dialog.getByRole("button", { name: "确认执行", exact: true }).click();
  await expect(dialog.getByRole("alert")).toContainText("原票据已保留");
  await expect(dialog.getByRole("button", { name: "返回", exact: true })).toBeDisabled();
  state.recoveryOffline = false;
  await dialog.getByRole("button", { name: "核对原票据结果", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(state.calls.filter((call) => call.path.endsWith("dispatcher-controls/confirm"))).toHaveLength(1);
});

test("an explicitly rejected ticket can be edited and the next confirm uses its new preview", async ({ page }) => {
  const state = await boot(page, "/app/control", (value) => { value.rejectConfirm = true; value.rotateTicket = true; });
  await page.getByRole("button", { name: "启动", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Dispatcher start" });
  await dialog.getByRole("textbox").fill("original reason");
  await dialog.getByRole("button", { name: "生成预览", exact: true }).click();
  await dialog.getByRole("button", { name: "确认执行", exact: true }).click();
  await expect(dialog.getByRole("alert")).toContainText("fresh preview");
  await dialog.getByRole("button", { name: "返回", exact: true }).click();
  await expect(dialog.getByRole("textbox")).toHaveValue("original reason");
  await dialog.getByRole("textbox").fill("revised reason");
  await dialog.getByRole("button", { name: "生成预览", exact: true }).click();
  await expect(dialog).toContainText("ticket-revised");
  await dialog.getByRole("button", { name: "确认执行", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  const confirmations = state.calls.filter((call) => call.path.endsWith("dispatcher-controls/confirm"));
  expect(confirmations.map((call) => JSON.parse(call.body).ticket_id)).toEqual(["ticket-original", "ticket-revised"]);
});

test("hidden tabs pause polling and return with one fresh read while preserving a draft", async ({ page }) => {
  await page.clock.install();
  const state = await boot(page, "/app/control");
  await page.getByRole("button", { name: "启动", exact: true }).click();
  const draft = page.getByRole("dialog", { name: "Dispatcher start" }).getByRole("textbox");
  await draft.fill("keep while hidden");
  const before = state.calls.filter((call) => call.path === "/v1/admin/control-runs").length;
  await page.evaluate(() => Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" }));
  await page.clock.runFor(16000);
  expect(state.calls.filter((call) => call.path === "/v1/admin/control-runs")).toHaveLength(before);
  await page.evaluate(() => { Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" }); document.dispatchEvent(new Event("visibilitychange")); dispatchEvent(new Event("focus")); dispatchEvent(new Event("online")); });
  await page.clock.runFor(200);
  await expect.poll(() => state.calls.filter((call) => call.path === "/v1/admin/control-runs").length).toBe(before + 1);
  await expect(draft).toHaveValue("keep while hidden");
});

test("SSE bursts coalesce relevant invalidations and ignore unrelated job events on Projects", async ({ page }) => {
  await installLiveStream(page);
  const state = await boot(page, "/app/projects");
  await expect(page.getByRole("heading", { name: "登记新项目", exact: true })).toBeVisible();
  const before = state.calls.filter((call) => call.path === "/v1/projects").length;
  const events = Array.from({ length: 10 }, (_, index) => ({ sequence: index + 1, event_id: `event-${index}`, event_type: index < 5 ? "job.updated" : "person_submission_policy.updated", subject_type: index < 5 ? "job" : "person", subject_id: "fixture" }));
  await page.evaluate((values) => values.forEach(window.__rcnEmitState), events);
  await expect.poll(() => state.calls.filter((call) => call.path === "/v1/me/submission-policy").length).toBe(2);
  expect(state.calls.filter((call) => call.path === "/v1/projects")).toHaveLength(before);
  expect(state.calls.filter((call) => call.path === "/v1/me")).toHaveLength(1);
  expect(state.calls.filter((call) => call.path === "/v1/jobs")).toHaveLength(0);
});

test("member double-clicks retain the original submission and recover its lost confirmation", async ({ page }) => {
  const member = await memberApiFixture(page, { lostConfirm: true });
  await boot(page, "/app/submit", (state) => { state.member = true; });
  await expect(page.getByRole("heading", { name: "我的计算额度", exact: true })).toBeVisible();
  await selectTaskPackage(page);
  await page.getByRole("button", { name: "生成提交预览", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(page.getByRole("button", { name: "确认提交", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "确认提交", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(page.getByText("响应中断，已恢复原提交记录。", { exact: true })).toBeVisible();
  expect(member.jobsCreated()).toBe(1);
  expect(member.calls.filter((call) => call.method === "PUT" && call.pathname.includes("/operations/"))).toHaveLength(1);
  expect(member.calls.filter((call) => call.method === "POST" && call.pathname.endsWith("/confirm"))).toHaveLength(1);
});

test("member contribution refresh retains unsaved resource preferences", async ({ page }) => {
  await memberApiFixture(page, { contribution: { configured: true, contribution_id: "93dd34d6-bfde-4e62-8324-1a3df535f659", revision: 0, machine_id: "fixture-machine", preferences: { max_cpus: 4, max_memory_mb: 4096 } } });
  await boot(page, "/app/contribution", (state) => { state.member = true; });
  const cpus = page.getByLabel("最多调度 CPU 线程", { exact: true });
  await expect(cpus).toHaveValue("4");
  await cpus.fill("7");
  await page.getByRole("button", { name: "刷新接入状态", exact: true }).click();
  await expect(cpus).toHaveValue("7");
});

for (const lostReply of [false, true]) {
  test(`token issuance and revocation reject same-frame duplicates${lostReply ? " and preserve an unknown issuance across reload" : ""}`, async ({ page }) => {
    const records = [];
    const state = await boot(page, "/app/admin", (value) => {
      value.respond = async ({ url, request, json, route }) => {
        if (!url.pathname.startsWith("/v1/users/member-a/tokens")) return false;
        if (request.method() === "POST") {
          records.push({ token_id: "token-fixture", user_id: "member-a", active: true, created_at: new Date().toISOString() });
          if (lostReply) { await route.abort(); return true; }
          await json({ token_id: "token-fixture", user_id: "member-a", token: "synthetic-only-token" });
        } else if (request.method() === "DELETE") { records[0].active = false; await json({ ...records[0] }); }
        else await json(records);
        return true;
      };
    });
    const issue = page.getByRole("button", { name: "签发", exact: true });
    await issue.evaluate((button) => { button.click(); button.click(); });
    if (lostReply) {
      await expect(page.getByText(/签发结果未知/)).toBeVisible();
      await expect(issue).toBeDisabled();
      await page.reload();
      await expect(page.getByRole("heading", { name: "Token 签发结果待核对", exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: "签发", exact: true })).toBeDisabled();
      await page.getByRole("button", { name: "核对现有 Token", exact: true }).click();
    } else await expect(page.getByText("synthetic-only-token", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "撤销", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "撤销", exact: true }).evaluate((button) => { button.click(); button.click(); });
    await expect(page.getByRole("button", { name: "撤销", exact: true })).toHaveCount(0);
    expect(state.calls.filter((call) => call.path === "/v1/users/member-a/tokens" && call.method === "POST")).toHaveLength(1);
    expect(state.calls.filter((call) => call.path.endsWith("/tokens/token-fixture") && call.method === "DELETE")).toHaveLength(1);
  });
}

const historicalConditionsJob = (id) => ({ ...makeJob(id), execution_environment: null, execution_environment_state: "not_requested", project_concurrency: null, project_concurrency_state: "not_requested" });

test("historical execution conditions stay manual coalesce clicks and retain the last check after a lost read", async ({ page }) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const state = await boot(page, "/app/runs?drawer=conditions-a", (value) => {
    value.history = [historicalConditionsJob("conditions-a")]; value.conditionReads = 0;
    value.respond = async ({ url, json, route }) => {
      if (url.pathname !== "/v1/jobs/conditions-a/execution-conditions") return false;
      value.conditionReads += 1;
      if (value.conditionReads === 1) await gate;
      if (value.failCheck) { await route.abort(); return true; }
      await json({ job_id: "conditions-a", generated_at: value.conditionReads === 1 ? "2026-10-17T12:00:00Z" : "2026-10-17T12:01:00Z", execution_environment: { status: "executable", capacity_hint: { eligible_slots: 2 } }, project_concurrency: { active_units: 1, prepared_units: 0, max_running_units: 4 } }); return true;
    };
  });
  const section = page.getByRole("region", { name: "当前执行条件检查", exact: true });
  await expect(section.getByRole("button", { name: "检查当前执行条件", exact: true })).toBeEnabled();
  await page.evaluate(() => { dispatchEvent(new CustomEvent("rcn:data-refresh", { detail: { resources: ["jobs"] } })); dispatchEvent(new Event("focus")); document.dispatchEvent(new Event("visibilitychange")); });
  await page.waitForTimeout(250);
  expect(state.conditionReads).toBe(0);
  await section.getByRole("button", { name: "检查当前执行条件", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect.poll(() => state.conditionReads).toBe(1);
  release();
  await expect(section).toContainText("环境就绪 · 2 可用 slot");
  await expect(section).toContainText("1 运行 + 0 预备 / 4 上限");
  await expect(section.locator("time")).toHaveAttribute("datetime", "2026-10-17T12:00:00Z");
  state.failCheck = true;
  await section.getByRole("button", { name: "检查当前执行条件", exact: true }).click();
  await expect(section.getByRole("alert")).toContainText("保留");
  await expect(section.locator("time")).toHaveAttribute("datetime", "2026-10-17T12:00:00Z");
  state.failCheck = false;
  await section.getByRole("button", { name: "检查当前执行条件", exact: true }).click();
  await expect(section.locator("time")).toHaveAttribute("datetime", "2026-10-17T12:01:00Z");
  expect(state.conditionReads).toBe(3);
});

test("an abandoned historical conditions read cannot populate a newly selected Job", async ({ page }) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const state = await boot(page, "/app/runs?drawer=conditions-a", (value) => {
    value.history = [historicalConditionsJob("conditions-a"), historicalConditionsJob("conditions-b")];
    value.respond = async ({ url, json }) => {
      const match = url.pathname.match(/^\/v1\/jobs\/(conditions-[ab])\/execution-conditions$/);
      if (!match) return false;
      if (match[1] === "conditions-a") await gate;
      try { await json({ job_id: match[1], generated_at: "2026-10-17T12:00:00Z", execution_environment: match[1] === "conditions-a" ? { status: "executable", capacity_hint: { eligible_slots: 7 } } : { status: "blocked_by_approval" }, project_concurrency: null }); } catch { /* Expected when the old Job's fetch was aborted. */ }
      return true;
    };
  });
  const button = () => page.getByRole("button", { name: "检查当前执行条件", exact: true });
  await button().click();
  await expect.poll(() => state.calls.some((call) => call.path === "/v1/jobs/conditions-a/execution-conditions")).toBe(true);
  await page.evaluate(() => { history.pushState({}, "", "/app/runs?drawer=conditions-b"); dispatchEvent(new PopStateEvent("popstate")); });
  await expect(page.locator(".drawer").getByRole("heading", { name: "conditions-b", exact: true })).toBeVisible();
  expect(state.calls.some((call) => call.path === "/v1/jobs/conditions-b/execution-conditions")).toBe(false);
  await button().click();
  const section = page.getByRole("region", { name: "当前执行条件检查", exact: true });
  await expect(section).toContainText("等待当前 Runtime 审批");
  release(); await page.waitForTimeout(100);
  await expect(section).not.toContainText("7 可用 slot");
  await expect(section).toContainText("未知 运行 + 未知 预备 / 未知 上限");
});

test("scheduling writes reject same-frame duplicates and recover the original lost response without another confirmation", async ({ page }) => {
  let original = null, receiptReady = false;
  const state = await boot(page, "/app/control", (value) => {
    value.scheduling = { revision: 1, policy: { strategy: "balanced", small_batch_max_units: 4, small_batch_max_serial_seconds: 1800, starvation_after_s: 7200 } };
    value.respond = async ({ url, request, json, route }) => {
      if (url.pathname === "/v1/admin/scheduling/preview") { await json({ confirmation_hash: "scheduling-hash" }); return true; }
      if (url.pathname === "/v1/admin/scheduling/confirm") {
        expect(original).toBeNull();
        value.scheduling = { revision: 2, policy: request.postDataJSON().policy };
        original = { request_id: request.headers()["x-rcn-request-id"], kind: "scheduling_confirm", subject_id: "global", state: "completed", result: structuredClone(value.scheduling) };
        await route.abort(); return true;
      }
      if (url.pathname.startsWith("/v1/metadata-operations/")) {
        expect(url.pathname).toBe(`/v1/metadata-operations/${original.request_id}`);
        await json(receiptReady ? original : { detail: "original scheduling receipt offline" }, receiptReady ? 200 : 503); return true;
      }
      return false;
    };
  });
  const panel = page.getByRole("region", { name: "调度策略设置" });
  await panel.getByLabel("变更原因", { exact: true }).fill("guard test");
  await panel.getByRole("button", { name: "预览调度策略", exact: true }).evaluate((button) => { button.click(); button.click(); });
  const confirm = panel.getByRole("button", { name: "确认应用策略", exact: true });
  await confirm.evaluate((button) => { button.click(); button.click(); });
  await expect(panel.getByRole("alert")).toContainText("核对原操作回执");
  await expect(panel.getByRole("button", { name: "等待原操作回执", exact: true })).toBeDisabled();
  const recovery = page.getByRole("status", { name: "管理操作回执" });
  await expect(recovery).toContainText("original scheduling receipt offline");
  state.scheduling = { revision: 3, policy: { ...state.scheduling.policy, strategy: "throughput" } };
  receiptReady = true;
  await recovery.getByRole("button", { name: "核对原操作", exact: true }).click();
  await expect(panel.getByRole("status")).toContainText("修订 2");
  await expect(panel.locator("header small")).toContainText("修订 3");
  await expect(panel.locator('input[value="throughput"]')).toBeChecked();
  expect(state.calls.filter((call) => call.path === "/v1/admin/scheduling/preview")).toHaveLength(1);
  const confirmations = state.calls.filter((call) => call.path === "/v1/admin/scheduling/confirm");
  expect(confirmations).toHaveLength(1);
  await page.reload();
  await expect(panel.locator("header small")).toContainText("修订 3");
  expect(state.calls.filter((call) => call.path === "/v1/admin/scheduling/confirm")).toHaveLength(1);
});

async function jobTransactionFixture(page, options = {}) {
  const job = { ...makeJob("job-a", "running"), work_units: [{ work_unit_id: "unit-a", ordinal: 0, status: "running", assigned_machine_id: "source", attempt_count: 1,
    attempts: [{ attempt_id: "attempt-a", external_run_id: "ssh-a", machine_id: "source", state: "running" }] }] };
  const other = { ...makeJob("job-b", "running"), work_units: [] };
  return boot(page, "/app/runs?drawer=job-a", (state) => {
    Object.assign(state, options); state.history = [job, other]; state.receipts = {}; state.reassignPosts = [];
    state.overview = { generated_at: new Date().toISOString(), summary: {}, policies: {}, machines: ["source", "target"].map((machine_id) => ({ machine_id, display_name: machine_id, metrics: {} })) };
    state.respond = async ({ url, request, json, route }) => {
      const selected = state.history.find((item) => url.pathname === `/v1/jobs/${item.job_id}`);
      if (selected) { await json(selected); return true; }
      if (url.pathname === "/v1/admin/operations/preview") {
        const body = request.postDataJSON();
        if (body.job_id === "job-a" && state.previewGate) await state.previewGate;
        await json({ ...body, job_id: state.wrongTicket ? "job-b" : body.job_id, ticket_id: `ticket-${body.job_id}`, confirmation_hash: "fixed-hash", issued_by: "fixture", impact: { affected_units: 1 } }); return true;
      }
      if (url.pathname === "/v1/admin/operations/confirm") {
        const body = request.postDataJSON(), id = body.ticket_id.replace("ticket-", ""), record = state.history.find((item) => item.job_id === id);
        record.status = "cancelled"; record.activity_state = "history";
        state.receipts[body.ticket_id] = { request_id: body.ticket_id, kind: "admin_job", subject_id: id, result_id: id, state: "completed" };
        if (state.dropJobConfirm) { await route.abort(); return true; }
        await json({ accepted: true, job: record }); return true;
      }
      if (url.pathname.startsWith("/v1/admin/metadata-operations/")) {
        if (state.recoveryOffline) await json({ detail: "receipt temporarily offline" }, 503);
        else await json(state.receipts[url.pathname.split("/").at(-1)] || { detail: "not accepted" }, state.receipts[url.pathname.split("/").at(-1)] ? 200 : 404);
        return true;
      }
      if (url.pathname === "/v1/jobs/job-a/units/unit-a/reassign") {
        const body = request.postDataJSON(); state.reassignPosts.push(body); state.reassignBody = body;
        if (state.reassignPosts.length === 1 || state.repeatCancel) {
          state.reassignStage = "cancel_requested"; job.work_units[0].attempts[0].state = "cancel_pending";
        } else { state.reassignStage = "reassigned"; job.status = "queued"; job.work_units[0].status = "queued"; job.work_units[0].assigned_machine_id = "target"; }
        if ((state.dropFirst && state.reassignPosts.length === 1) || (state.dropSecond && state.reassignPosts.length === 2)) { await route.abort(); return true; }
        await json({ ...body, stage: state.reassignStage, job }); return true;
      }
      if (url.pathname.includes("/reassign-operations/")) {
        if (state.reassignReadOffline) { await json({ detail: "original operation temporarily offline" }, 503); return true; }
        if (!state.reassignBody) { await json({ detail: "not accepted" }, 404); return true; }
        if (state.drift) job.work_units[0].attempts.push({ attempt_id: "attempt-successor", external_run_id: "ssh-successor", state: "running" });
        else if (state.ready !== false && state.reassignStage !== "reassigned") { job.work_units[0].status = "cancelled"; job.work_units[0].attempts[0].state = "cancelled"; }
        await json({ ...state.reassignBody, stage: state.reassignStage, job }); return true;
      }
      return false;
    };
  });
}

test("a late Job A preview cannot enter Job B drawer or confirm A through B", async ({ page }) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const state = await jobTransactionFixture(page, { previewGate: gate });
  const drawer = page.locator(".drawer");
  await drawer.getByRole("button", { name: "取消 Job", exact: true }).click();
  await drawer.getByLabel("取消原因", { exact: true }).fill("cancel original A");
  await drawer.getByRole("button", { name: "生成预览", exact: true }).click();
  await expect.poll(() => state.calls.filter((call) => call.path === "/v1/admin/operations/preview").length).toBe(1);
  await page.evaluate(() => { history.pushState({}, "", "/app/runs?drawer=job-b"); dispatchEvent(new PopStateEvent("popstate")); });
  await expect(drawer.getByRole("heading", { name: "job-b", exact: true })).toBeVisible();
  release(); await page.waitForTimeout(100);
  await expect(drawer.getByRole("button", { name: "确认执行", exact: true })).toHaveCount(0);
  await drawer.getByRole("button", { name: "取消 Job", exact: true }).click();
  await drawer.getByLabel("取消原因", { exact: true }).fill("cancel B explicitly");
  await drawer.getByRole("button", { name: "生成预览", exact: true }).click();
  await drawer.getByRole("button", { name: "确认执行", exact: true }).click();
  expect(state.calls.filter((call) => call.path === "/v1/admin/operations/confirm").map((call) => JSON.parse(call.body).ticket_id)).toEqual(["ticket-job-b"]);
});

test("Job drawer rejects a preview ticket bound to another Job", async ({ page }) => {
  const state = await jobTransactionFixture(page, { wrongTicket: true });
  const drawer = page.locator(".drawer");
  await drawer.getByRole("button", { name: "取消 Job", exact: true }).click();
  await drawer.getByLabel("取消原因", { exact: true }).fill("cancel A");
  await drawer.getByRole("button", { name: "生成预览", exact: true }).click();
  await expect(drawer).toContainText("预览票据与当前 Job 或操作者不匹配");
  await expect(drawer.getByRole("button", { name: "确认执行", exact: true })).toHaveCount(0);
  expect(state.calls.filter((call) => call.path === "/v1/admin/operations/confirm")).toHaveLength(0);
});

test("Job confirmation survives lost reply and reload using only the original receipt query", async ({ page }) => {
  const state = await jobTransactionFixture(page, { dropJobConfirm: true, recoveryOffline: true });
  const drawer = page.locator(".drawer");
  await drawer.getByRole("button", { name: "取消 Job", exact: true }).click();
  await drawer.getByLabel("取消原因", { exact: true }).fill("durable original cancellation");
  await drawer.getByRole("button", { name: "生成预览", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await drawer.getByRole("button", { name: "确认执行", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(drawer).toContainText("原操作已保留");
  await page.reload();
  // Wait for the automatic recovery read to fail before enabling its fixture.
  // The button's first render can precede the recovery effect acquiring busy.
  await expect(drawer).toContainText("receipt temporarily offline");
  await expect(drawer.getByRole("button", { name: "核对原操作结果", exact: true })).toBeEnabled();
  state.recoveryOffline = false;
  await drawer.getByRole("button", { name: "核对原操作结果", exact: true }).click();
  await expect(drawer).toContainText("原 Job 操作已完成");
  expect(state.calls.filter((call) => call.path === "/v1/admin/operations/preview")).toHaveLength(1);
  expect(state.calls.filter((call) => call.path === "/v1/admin/operations/confirm")).toHaveLength(1);
  const metadataIndex = state.calls.findLastIndex((call) => call.path === "/v1/admin/metadata-operations/ticket-job-a");
  expect(state.calls.slice(metadataIndex + 1).some((call) => call.path === "/v1/jobs/job-a")).toBe(true);
});

async function beginReassignment(page) {
  const drawer = page.locator(".drawer");
  await drawer.getByTitle("改派到其他机器", { exact: true }).click();
  await drawer.locator(".reassign-panel select").selectOption("target");
  await drawer.getByLabel("改派原因（审计必填）", { exact: true }).fill("move original attempt only");
  await drawer.getByRole("button", { name: "确认改派", exact: true }).evaluate((button) => { button.click(); button.click(); });
  return drawer;
}

test("reassignment continues one frozen operation after a lost reply and reload", async ({ page }) => {
  const state = await jobTransactionFixture(page, { dropFirst: true, reassignReadOffline: true });
  const drawer = await beginReassignment(page);
  await expect(drawer).toContainText("原操作已保留");
  const original = state.reassignPosts[0];
  await page.reload();
  await expect(drawer.getByRole("button", { name: "核对原改派", exact: true })).toBeEnabled();
  expect(state.reassignPosts).toHaveLength(1);
  state.reassignReadOffline = false;
  await drawer.getByRole("button", { name: "核对原改派", exact: true }).click();
  await expect(drawer).toContainText("原改派仍在等待取消传播");
  expect(state.reassignPosts).toHaveLength(1);
  await drawer.getByRole("button", { name: "继续原改派", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(drawer).toContainText("原单元改派已完成");
  expect(state.reassignPosts).toEqual([original, original]);
  expect(original).toMatchObject({ expected_attempt_id: "attempt-a", expected_external_run_id: "ssh-a", target_machine_id: "target" });
  expect(original.operation_id).toMatch(/^[0-9a-f-]{36}$/);
});

test("reassignment stops before a successor Attempt and retains the original identity", async ({ page }) => {
  await page.clock.install();
  const state = await jobTransactionFixture(page, { drift: true });
  const drawer = await beginReassignment(page);
  await expect.poll(() => state.reassignPosts.length).toBe(1);
  await page.clock.runFor(2100);
  await expect(drawer).toContainText("原尝试已变更");
  await drawer.getByRole("button", { name: "继续原改派", exact: true }).click();
  await expect(drawer).toContainText("原尝试已变更");
  expect(state.reassignPosts).toHaveLength(1);
  await expect(drawer.locator(".reassign-panel select")).toBeDisabled();
});

test("a second cancel_requested response never completes reassignment or creates a new operation", async ({ page }) => {
  await page.clock.install();
  const state = await jobTransactionFixture(page, { repeatCancel: true });
  const drawer = await beginReassignment(page);
  await expect.poll(() => state.reassignPosts.length).toBe(1);
  await page.clock.runFor(2100);
  await expect(drawer).toContainText("原改派没有完成");
  expect(state.reassignPosts).toHaveLength(2);
  await expect(drawer.getByRole("button", { name: "继续原改派", exact: true })).toBeVisible();
  state.repeatCancel = false;
  await drawer.getByRole("button", { name: "继续原改派", exact: true }).click();
  await expect(drawer).toContainText("原单元改派已完成");
  expect(state.reassignPosts).toEqual(Array(3).fill(state.reassignPosts[0]));
});

test("a lost second-stage reassignment response recovers the completed original operation", async ({ page }) => {
  await page.clock.install();
  const state = await jobTransactionFixture(page, { dropSecond: true });
  const drawer = await beginReassignment(page);
  await expect.poll(() => state.reassignPosts.length).toBe(1);
  await page.clock.runFor(2100);
  await expect(drawer).toContainText("原单元改派已完成");
  expect(state.reassignPosts).toEqual([state.reassignPosts[0], state.reassignPosts[0]]);
});

test("Projects preserves enrollment history and directs new installations to v2 invitations", async ({ page }) => {
  const state = await boot(page, "/app/projects", (value) => {
    value.respond = async ({ url, json }) => {
      if (url.pathname !== "/v1/me/enrollments") return false;
      await json([{ enrollment_id: "old", machine_id: "historical-node", used_at: "2026-10-01T00:00:00Z" }]); return true;
    };
  });
  await expect(page.getByRole("heading", { name: "我的机器接入记录", exact: true })).toBeVisible();
  await expect(page.getByText("historical-node", { exact: true })).toBeVisible();
  await expect(page.getByText("新机器请向管理员领取私密 v2 成员邀请，使用通用安装包接入。", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "生成 30 分钟准入码", exact: true })).toHaveCount(0);
  expect(state.calls.filter((call) => call.path === "/v1/me/enrollments" && call.method === "POST")).toHaveLength(0);
});

for (const accepted of [true, false]) {
  test(`pressure override retains its original ticket after a lost reply and ${accepted ? "recovers by read after reload" : "retries only the same confirmation"}`, async ({ page }) => {
    const machineId = "pressure-node", originalUntil = "2026-10-17T23:30:00Z";
    const state = await boot(page, `/app/fleet?drawer=${machineId}`, (value) => {
      value.recoveryOffline = accepted;
      value.overview = { generated_at: new Date().toISOString(), summary: {}, machines: [{ machine_id: machineId, display_name: machineId, owner_user_id: "fixture", total_cpus: 8, total_memory_mb: 8192, metrics: { available: true } }],
        policies: { [machineId]: { owner_mode: "open", max_concurrent_units: 4 } }, execution_configs: { [machineId]: { max_concurrent_units: 4, target_concurrent_units: 2 } },
        operational_statuses: { [machineId]: { machine_id: machineId, supervisor_state: "online", telemetry_state: "live", effective_capacity: 2 } } };
      value.respond = async ({ url, request, json, route }) => {
        if (url.pathname.endsWith("/pressure-override/preview")) { await json({ ...request.postDataJSON(), machine_id: machineId, ticket_id: "pressure-ticket", confirmation_hash: "pressure-hash", requested_until: originalUntil }); return true; }
        if (url.pathname.endsWith("/pressure-override/confirm")) {
          value.confirmCount = (value.confirmCount || 0) + 1;
          if (accepted || value.confirmCount > 1) value.pressureReceipt = { request_id: "pressure-ticket", kind: "pressure_override", subject_id: machineId, result_id: machineId, state: "completed", requested_until: originalUntil, result: { machine_id: machineId, pressure_override_until: originalUntil } };
          if (value.confirmCount === 1) await route.abort(); else await json(value.pressureReceipt.result);
          return true;
        }
        if (url.pathname === "/v1/admin/metadata-operations/pressure-ticket") {
          if (value.recoveryOffline) await json({ detail: "receipt offline" }, 503);
          else await json(value.pressureReceipt || { detail: "not yet accepted" }, value.pressureReceipt ? 200 : 404);
          return true;
        }
        return false;
      };
    });
    const drawer = page.locator(".drawer");
    await drawer.getByLabel("审计原因", { exact: true }).fill("temporary original override");
    await drawer.getByRole("button", { name: "预览影响", exact: true }).evaluate((button) => { button.click(); button.click(); });
    await drawer.getByRole("button", { name: "确认覆盖", exact: true }).evaluate((button) => { button.click(); button.click(); });
    await expect(drawer).toContainText("原票据已保留");
    await expect(drawer.getByRole("button", { name: "返回修改", exact: true })).toBeDisabled();
    if (accepted) {
      await page.reload();
      await expect(drawer).toContainText("receipt offline");
      await expect(drawer.getByRole("button", { name: "核对原覆盖结果", exact: true })).toBeEnabled();
      expect(state.confirmCount).toBe(1);
      state.recoveryOffline = false;
      await drawer.getByRole("button", { name: "核对原覆盖结果", exact: true }).click();
    } else await drawer.getByRole("button", { name: "重试原覆盖票据", exact: true }).click();
    await expect(drawer).toContainText("原压力覆盖已确认");
    const confirmations = state.calls.filter((call) => call.path.endsWith("/pressure-override/confirm"));
    expect(confirmations).toHaveLength(accepted ? 1 : 2);
    expect(confirmations.every((call) => call.body === confirmations[0].body)).toBe(true);
    expect(state.calls.filter((call) => call.path.endsWith("/pressure-override/preview"))).toHaveLength(1);
    expect(state.pressureReceipt.requested_until).toBe(originalUntil);
  });
}

test("stale insights display the last-good charts then recover the new generation without overlapping reads", async ({ page }) => {
  const previous = makeInsightsFixture(), next = makeInsightsFixture();
  previous.generated_at = new Date(Date.now() - 17000).toISOString(); previous.overall.active_jobs = 3;
  previous.read_state = { stale: true, refreshing: true, age_seconds: 17, last_success_at: previous.generated_at, refresh_error: null };
  next.generated_at = new Date().toISOString(); next.overall.active_jobs = 12;
  next.read_state = { stale: false, refreshing: false, age_seconds: 0, last_success_at: next.generated_at, refresh_error: null };
  let release, reads = 0;
  const gate = new Promise((resolve) => { release = resolve; });
  const state = await boot(page, "/app/overview", (value) => {
    value.insights = async () => { reads += 1; if (reads === 1) return previous; await gate; return next; };
  });
  await expect(page.locator(".insight-stat").first()).toContainText("3 个 Job");
  await expect(page.locator(".insight-warning")).toContainText("统计正在后台更新");
  await expect(page.locator(".insight-stat").last()).toContainText("待刷新");
  await expect(page.locator(".insight-chart svg").first()).toBeVisible();
  await expect(page.locator(".insight-footnote time")).toHaveAttribute("datetime", previous.generated_at);
  await expect.poll(() => reads).toBe(2);
  await page.waitForTimeout(900);
  expect(reads).toBe(2);
  release();
  await expect(page.locator(".insight-stat").first()).toContainText("12 个 Job");
  await expect(page.locator(".insight-warning")).toHaveCount(0);
  await expect(page.locator(".insight-stat").last()).not.toContainText("待刷新");
  await expect(page.locator(".insight-footnote time")).toHaveAttribute("datetime", next.generated_at);
  expect(state.calls.filter((call) => call.path === "/v1/operations/insights")).toHaveLength(2);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});

test("failed insights background refresh keeps its snapshot and stops rapid follow-up reads", async ({ page }) => {
  await page.clock.install();
  const previous = makeInsightsFixture(); previous.generated_at = new Date(Date.now() - 17000).toISOString();
  previous.read_state = { stale: true, refreshing: true, age_seconds: 17, last_success_at: previous.generated_at, refresh_error: null };
  let reads = 0;
  await boot(page, "/app/overview", (value) => {
    value.insights = () => { reads += 1; return reads === 1 ? previous : { ...previous, read_state: { ...previous.read_state, refreshing: false, refresh_error: "RuntimeError" } }; };
  });
  await expect(page.locator(".insight-warning")).toContainText("统计正在后台更新");
  await page.clock.runFor(800);
  await expect(page.locator(".insight-warning")).toContainText("后台更新失败");
  await expect(page.locator(".insight-warning")).toContainText("RuntimeError");
  await expect(page.locator(".insight-stat")).toHaveCount(4);
  await expect(page.locator(".insight-stat").last()).toContainText("待刷新");
  await expect(page.locator(".insight-footnote time")).toHaveAttribute("datetime", previous.generated_at);
  await page.clock.runFor(5000);
  expect(reads).toBe(2);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});

test("shared Dispatcher checkpoint survives reload and queries its original ticket before any new intent", async ({ page }) => {
  const state = await boot(page, "/app/control", (value) => { value.dropConfirm = true; value.recoveryOffline = true; });
  const open = () => page.getByRole("button", { name: "启动", exact: true }).click();
  await open();
  const dialog = page.getByRole("dialog", { name: "Dispatcher start" });
  await dialog.getByRole("button", { name: "生成预览", exact: true }).click();
  await dialog.getByRole("button", { name: "确认执行", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(dialog).toContainText("原票据已保留");
  await page.reload(); await open();
  await expect(dialog).toContainText("ticket-original");
  await expect(dialog.getByRole("button", { name: "核对原票据结果", exact: true })).toBeEnabled();
  await expect(dialog.getByRole("button", { name: "生成预览", exact: true })).toHaveCount(0);
  state.recoveryOffline = false;
  await dialog.getByRole("button", { name: "核对原票据结果", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(state.calls.filter((call) => call.path.endsWith("dispatcher-controls/preview"))).toHaveLength(1);
  expect(state.calls.filter((call) => call.path.endsWith("dispatcher-controls/confirm"))).toHaveLength(1);
});

test("emergency control restores only nonsecret ticket data and requires a new PIN for explicit continuation", async ({ page }) => {
  const machine = { machine_id: "pin-machine", display_name: "pin-machine", owner_user_id: "fixture", metrics: {} };
  const state = await boot(page, "/app/machines/pin-machine?tab=control", (value) => {
    value.confirmBodies = [];
    value.respond = async ({ url, request, json, route }) => {
      if (url.pathname === "/v1/machines/pin-machine/detail") { await json({ machine, events: [], jobs: [], policy: { max_concurrent_units: 4 }, execution_config: { max_concurrent_units: 4 } }); return true; }
      if (url.pathname === "/v1/admin/machine-controls/preview") {
        await json({ ...request.postDataJSON(), ticket_id: "pin-ticket", confirmation_hash: "pin-hash", issued_by: "fixture", requires_break_glass: true, impact: { "pin-machine": { external_comsol_process_set_hash: "original-processes" } } }); return true;
      }
      if (url.pathname === "/v1/admin/machine-controls/confirm") {
        value.confirmBodies.push(request.postDataJSON());
        if (value.confirmBodies.length === 1) { await route.abort(); return true; }
        value.pinRun = { operation_id: "pin-operation", ticket_id: "pin-ticket", action: "emergency_stop_host", requested_by: "fixture", targets: [{ machine_id: "pin-machine" }] };
        await json(value.pinRun); return true;
      }
      if (url.pathname === "/v1/admin/control-runs/by-ticket/pin-ticket") { await json(value.pinRun || { detail: "not yet known" }, value.pinRun ? 200 : 404); return true; }
      return false;
    };
  });
  const open = () => page.getByRole("button", { name: "主机 COMSOL 终止", exact: true }).click();
  await open();
  const dialog = page.getByRole("dialog", { name: "主机 COMSOL 紧急终止", exact: true });
  await dialog.getByRole("textbox").first().fill("explicit emergency test");
  await dialog.getByRole("button", { name: "生成预览", exact: true }).click();
  await dialog.getByLabel("完整机器 ID", { exact: true }).fill("pin-machine");
  await dialog.getByLabel("独立应急 PIN", { exact: true }).fill("synthetic-old-pin");
  await dialog.getByRole("button", { name: "确认执行", exact: true }).click();
  await expect(dialog).toContainText("原票据已保留");
  expect(await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }))).not.toContain("synthetic-old-pin");
  await page.reload(); await open();
  await expect(dialog).toContainText("pin-ticket");
  await expect(dialog.getByLabel("独立应急 PIN", { exact: true })).toHaveValue("");
  await expect(dialog.getByRole("button", { name: "确认执行", exact: true })).toBeDisabled();
  expect(state.confirmBodies).toHaveLength(1);
  await dialog.getByLabel("完整机器 ID", { exact: true }).fill("pin-machine");
  await dialog.getByLabel("独立应急 PIN", { exact: true }).fill("synthetic-new-pin");
  await dialog.getByRole("button", { name: "确认执行", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(dialog).toHaveCount(0);
  expect(state.confirmBodies).toHaveLength(2);
  expect(state.confirmBodies.map(({ break_glass_pin, ...body }) => body)).toEqual(Array(2).fill({ ticket_id: "pin-ticket", confirmation_hash: "pin-hash", typed_machine_id: "pin-machine", process_set_hash: "original-processes" }));
  expect(state.confirmBodies[1].break_glass_pin).toBe("synthetic-new-pin");
  expect(state.calls.filter((call) => call.path === "/v1/admin/machine-controls/preview")).toHaveLength(1);
});

test("runtime control reentry recovers its original ticket without another preview or confirm", async ({ page }) => {
  const state = await boot(page, "/app/control/runtime-failed", (value) => {
    value.runtimeOffline = true;
    value.respond = async ({ url, request, json, route }) => {
      const base = { operation_id: "runtime-failed", ticket_id: "previous", action: "promote_runtime", state: "failed", requested_by: "fixture", targets: [{ machine_id: "runtime-machine", state: "failed" }] };
      if (url.pathname === "/v1/admin/control-runs/runtime-failed") { await json(base); return true; }
      if (url.pathname.endsWith("/runtime-controls/preview")) { await json({ ...request.postDataJSON(), ticket_id: "runtime-ticket", confirmation_hash: "runtime-hash", issued_by: "fixture", targets: [{ machine_id: "runtime-machine" }], impact: {} }); return true; }
      if (url.pathname.endsWith("/runtime-controls/confirm")) { value.runtimeRun = { ...base, operation_id: "runtime-original", ticket_id: "runtime-ticket", state: "accepted" }; await route.abort(); return true; }
      if (url.pathname === "/v1/admin/control-runs/by-ticket/runtime-ticket") { await json(value.runtimeOffline ? { detail: "offline" } : value.runtimeRun, value.runtimeOffline ? 503 : 200); return true; }
      return false;
    };
  });
  const open = () => page.getByRole("button", { name: "仅重试失败目标", exact: true }).click();
  await open();
  const dialog = page.getByRole("dialog", { name: "runtime-machine runtime control", exact: true });
  await dialog.getByRole("textbox").fill("retry original failed runtime target");
  await dialog.getByRole("button", { name: "生成预览", exact: true }).click();
  await dialog.getByRole("button", { name: "确认执行", exact: true }).click();
  await expect(dialog).toContainText("原票据已保留");
  await page.reload(); await open();
  await expect(dialog).toContainText("runtime-ticket");
  state.runtimeOffline = false;
  await dialog.getByRole("button", { name: "核对原票据结果", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(state.calls.filter((call) => call.path.endsWith("/runtime-controls/preview"))).toHaveLength(1);
  expect(state.calls.filter((call) => call.path.endsWith("/runtime-controls/confirm"))).toHaveLength(1);
});

for (const accepted of [true, false]) {
  test(`Solver approval freezes issuance UUID across lost response and reload with ${accepted ? "revoked receipt recovery" : "explicit same-request retry"}`, async ({ page }) => {
    const state = await boot(page, "/app/admin?tab=approvals", (value) => {
      value.approvalPosts = []; value.approvalOffline = accepted; value.approvals = [];
      value.respond = async ({ url, request, json, route }) => {
        if (url.pathname === "/v1/solver-approvals") {
          if (request.method() === "POST") {
            const body = request.postDataJSON(), id = request.headers()["x-rcn-request-id"]; value.approvalPosts.push({ id, body });
            if (accepted || value.approvalPosts.length > 1) {
              value.approvals = [{ ...body, approval_id: "approval-original", active: !accepted, fingerprint: "fingerprint" }];
              value.approvalReceipt = { request_id: id, kind: "solver_approval", result_id: "approval-original", state: "completed" };
            }
            if (value.approvalPosts.length === 1) await route.abort(); else await json(value.approvals[0]);
          } else await json(value.approvals);
          return true;
        }
        if (url.pathname.startsWith("/v1/admin/metadata-operations/")) {
          if (value.approvalOffline) await json({ detail: "offline" }, 503);
          else await json(value.approvalReceipt || { detail: "not accepted" }, value.approvalReceipt ? 200 : 404);
          return true;
        }
        return false;
      };
    });
    const form = page.locator(".approval-form");
    await form.getByLabel("项目", { exact: true }).fill("approval-project");
    await form.getByLabel("执行 Profile", { exact: true }).fill("fixed-profile");
    await form.getByLabel("模板 SHA-256", { exact: true }).fill("a".repeat(64));
    await form.getByRole("button", { name: "签发审批", exact: true }).evaluate((button) => { button.click(); button.click(); });
    await expect(page.getByText("原 Solver 审批结果待核对", { exact: true })).toBeVisible();
    await page.reload();
    await expect(page.getByRole("button", { name: "核对原审批结果", exact: true })).toBeEnabled();
    expect(state.approvalPosts).toHaveLength(1);
    if (accepted) { state.approvalOffline = false; await page.getByRole("button", { name: "核对原审批结果", exact: true }).click(); }
    else await page.getByRole("button", { name: "重试原审批请求", exact: true }).evaluate((button) => { button.click(); button.click(); });
    await expect(page.locator(".inline-success")).toContainText("approval-original");
    if (accepted) await expect(page.locator(".inline-success")).toContainText("已撤销，不会重新激活");
    expect(state.approvalPosts).toEqual(Array(accepted ? 1 : 2).fill(state.approvalPosts[0]));
    expect(state.approvalPosts[0].id).toMatch(/^[0-9a-f-]{36}$/);
    expect(state.approvalPosts[0].body).not.toHaveProperty("approval_id");
  });
}

for (const conflict of [false, true]) {
  test(`alert transition preserves frozen CAS and deadline after ${conflict ? "a state conflict" : "lost reply and reload"}`, async ({ page }) => {
    const alert = { alert_id: "alert-original", status: "active", severity: "warning", subject_type: "machine", subject_id: "machine", kind: "pressure", message: "fixture alert", last_seen_at: "2026-10-17T12:00:00Z", occurrence_count: 1, acknowledged_at: null, snoozed_until: null, resolved_at: null };
    const state = await boot(page, "/app/alerts", (value) => {
      value.alertPosts = [];
      value.respond = async ({ url, request, json, route }) => {
        if (url.pathname === "/v1/admin/alerts") { await json([alert]); return true; }
        if (url.pathname.endsWith("/alerts/alert-original/transition")) {
          const body = request.postDataJSON(); value.alertPosts.push(body);
          if (value.alertPosts.length === 1) {
            if (conflict) { alert.status = "snoozed"; alert.last_seen_at = "2026-10-17T12:01:00Z"; alert.occurrence_count = 2; alert.snoozed_until = "2026-10-17T13:01:00Z"; await json({ detail: "alert_changed" }, 409); }
            else await route.abort();
          } else { alert.status = body.status; alert.snoozed_until = body.snoozed_until; value.alertReceipt = { request_id: body.request_id, kind: "alert_transition", subject_id: alert.alert_id, result_id: alert.alert_id, state: "completed" }; await json(alert); }
          return true;
        }
        if (url.pathname.startsWith("/v1/admin/metadata-operations/")) { await json(value.alertReceipt || { detail: "not accepted" }, value.alertReceipt ? 200 : 404); return true; }
        return false;
      };
    });
    await page.getByRole("button", { name: "暂缓 1h", exact: true }).evaluate((button) => { button.click(); button.click(); });
    if (conflict) {
      await expect(page.locator(".inline-error")).toContainText("原告警已变化");
      expect(state.alertPosts).toHaveLength(1);
      await expect(page.getByRole("button", { name: "重试原告警操作", exact: true })).toHaveCount(0);
      await page.getByRole("button", { name: "已核对，结束原操作", exact: true }).click();
      await page.getByRole("button", { name: "标记解决", exact: true }).click();
      await expect(page.getByRole("status")).toContainText("原告警操作已核对");
      expect(state.alertPosts[1].request_id).not.toBe(state.alertPosts[0].request_id);
      expect(state.alertPosts[1]).toMatchObject({ expected_status: "snoozed", expected_occurrence_count: 2, expected_last_seen_at: "2026-10-17T12:01:00Z", expected_snoozed_until: "2026-10-17T13:01:00Z" });
    } else {
      await expect(page.locator(".inline-error")).toContainText("原请求和绝对暂缓期限已保留");
      await page.reload();
      await expect(page.getByRole("button", { name: "重试原告警操作", exact: true })).toBeEnabled();
      expect(state.alertPosts).toHaveLength(1);
      await page.getByRole("button", { name: "重试原告警操作", exact: true }).evaluate((button) => { button.click(); button.click(); });
      await expect(page.getByRole("status")).toContainText("原告警操作已核对");
      expect(state.alertPosts).toEqual([state.alertPosts[0], state.alertPosts[0]]);
    }
    expect(state.alertPosts[0]).toMatchObject({ expected_status: "active", expected_last_seen_at: "2026-10-17T12:00:00Z", expected_occurrence_count: 1, expected_acknowledged_at: null, expected_snoozed_until: null, expected_resolved_at: null });
  });
}

test("a different actor never restores another actor's control approval or alert checkpoints", async ({ page }) => {
  await page.addInitScript(() => {
    const scope = { kind: "dispatcher", action: "start", machine_ids: [] };
    sessionStorage.setItem(`rcn-control:fixture:${encodeURIComponent(JSON.stringify(scope))}`, JSON.stringify({ actor_id: "fixture", scope, ticket: { ticket_id: "actor-control-ticket", confirmation_hash: "hash", action: "start", issued_by: "fixture" }, body: { ticket_id: "actor-control-ticket", confirmation_hash: "hash" } }));
    sessionStorage.setItem("rcn-solver-approval:fixture", JSON.stringify({ actor_id: "fixture", request_id: "11111111-1111-4111-8111-111111111111", payload: { approved_by: "fixture", project_id: "old-project", execution_profile_id: "old-profile" }, draft: {} }));
    sessionStorage.setItem("rcn-alert-transitions:fixture", JSON.stringify({ "old-alert": { actor_id: "fixture", alert_id: "old-alert", body: { request_id: "22222222-2222-4222-8222-222222222222", status: "resolved", snoozed_until: null, expected_status: "active", expected_last_seen_at: "2026-10-17T12:00:00Z", expected_occurrence_count: 1, expected_acknowledged_at: null, expected_snoozed_until: null, expected_resolved_at: null } } }));
  });
  const state = await boot(page, "/app/control", (value) => { value.me = { actor_id: "other-actor", roles: ["admin", "member"] }; });
  await page.getByRole("button", { name: "启动", exact: true }).click();
  await expect(page.getByRole("dialog").getByRole("button", { name: "生成预览", exact: true })).toBeEnabled();
  await page.goto("http://rcn-ui.test/app/admin?tab=approvals");
  await expect(page.locator(".approval-form")).toBeVisible();
  await expect(page.getByText("原 Solver 审批结果待核对", { exact: true })).toHaveCount(0);
  await page.goto("http://rcn-ui.test/app/alerts");
  await expect(page.getByText("当前没有告警", { exact: true })).toBeVisible();
  await expect(page.getByText("原告警操作待核对：old-alert", { exact: true })).toHaveCount(0);
  expect(state.calls.some((call) => call.path.includes("actor-control-ticket") || call.path.includes("11111111-1111") || call.path.includes("22222222-2222"))).toBe(false);
  expect(state.calls.some((call) => call.method === "POST")).toBe(false);
  expect(await page.evaluate(() => sessionStorage.getItem("rcn-solver-approval:fixture"))).toContain("old-project");
});

test("a definitively rejected Solver request permits editing only after explicitly ending that request", async ({ page }) => {
  const state = await boot(page, "/app/admin?tab=approvals", (value) => {
    value.approvalPosts = []; value.approvals = [];
    value.respond = async ({ url, request, json }) => {
      if (url.pathname === "/v1/solver-approvals") {
        if (request.method() === "POST") {
          const body = request.postDataJSON(); value.approvalPosts.push({ id: request.headers()["x-rcn-request-id"], body });
          if (value.approvalPosts.length === 1) await json({ detail: "template contract rejected" }, 422);
          else { value.approvals = [{ ...body, approval_id: "approval-corrected", active: true, fingerprint: "fingerprint" }]; await json(value.approvals[0]); }
        } else await json(value.approvals);
        return true;
      }
      if (url.pathname.startsWith("/v1/admin/metadata-operations/")) { await json({ detail: "not accepted" }, 404); return true; }
      return false;
    };
  });
  const form = page.locator(".approval-form");
  await form.getByLabel("项目", { exact: true }).fill("project");
  await form.getByLabel("执行 Profile", { exact: true }).fill("fixed-profile");
  await form.getByLabel("模板 SHA-256", { exact: true }).fill("b".repeat(64));
  await form.getByRole("button", { name: "签发审批", exact: true }).click();
  await expect(page.locator(".inline-error")).toContainText("原审批请求已明确被拒绝");
  await expect(form.getByLabel("COMSOL 版本", { exact: true })).toBeDisabled();
  expect(state.approvalPosts).toHaveLength(1);
  await page.getByRole("button", { name: "结束被拒绝的审批请求", exact: true }).click();
  await form.getByLabel("COMSOL 版本", { exact: true }).fill("6.3");
  await form.getByRole("button", { name: "签发审批", exact: true }).click();
  await expect(page.locator(".inline-success")).toContainText("approval-corrected");
  expect(state.approvalPosts).toHaveLength(2);
  expect(state.approvalPosts[1].id).not.toBe(state.approvalPosts[0].id);
  expect(state.approvalPosts[1].body.comsol_version).toBe("6.3");
});

for (const lostReply of [false, true]) {
  test(`Agent Token shares the per-user issuance guard and ${lostReply ? "blocks both scopes after a lost response and reload" : "displays one plaintext and revocable scopes"}`, async ({ page }) => {
    const records = [];
    const state = await boot(page, "/app/admin", (value) => {
      value.respond = async ({ url, request, json, route }) => {
        if (!url.pathname.startsWith("/v1/users/member-a/tokens")) return false;
        if (request.method() === "POST") {
          records.push({ token_id: "agent-token", user_id: "member-a", scopes: ["api", "agent"], active: true });
          if (lostReply) await route.abort(); else await json({ token_id: "agent-token", user_id: "member-a", token: "synthetic-agent-plaintext" });
        } else if (request.method() === "DELETE") { records[0].active = false; await json(records[0]); }
        else await json(records);
        return true;
      };
    });
    await expect(page.getByText("Agent Token 只用于该用户本人获准的计算，可单独撤销；不具管理员或机器所有者管理权限。", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "签发 Agent Token", exact: true }).evaluate((agent) => {
      const ordinary = [...document.querySelectorAll("button")].find((button) => button.textContent.trim() === "签发");
      agent.click(); ordinary.click(); agent.click();
    });
    if (lostReply) {
      await expect(page.getByText(/签发结果未知/)).toBeVisible();
      await page.reload();
      await expect(page.getByRole("button", { name: "签发 Agent Token", exact: true })).toBeDisabled();
      await expect(page.getByRole("button", { name: "签发", exact: true })).toBeDisabled();
      await page.getByRole("button", { name: "核对现有 Token", exact: true }).click();
    } else await expect(page.getByText("synthetic-agent-plaintext", { exact: true })).toBeVisible();
    await expect(page.locator(".token-panel")).toContainText("范围 api · agent");
    await page.getByRole("button", { name: "撤销", exact: true }).evaluate((button) => { button.click(); button.click(); });
    await expect(page.getByRole("button", { name: "撤销", exact: true })).toHaveCount(0);
    const posts = state.calls.filter((call) => call.path === "/v1/users/member-a/tokens" && call.method === "POST");
    expect(posts).toHaveLength(1); expect(JSON.parse(posts[0].body)).toEqual({ agent: true });
    expect(state.calls.filter((call) => call.path.endsWith("/tokens/agent-token") && call.method === "DELETE")).toHaveLength(1);
    expect(await page.evaluate(() => JSON.stringify({ ...sessionStorage }))).not.toContain("synthetic-agent-plaintext");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  });
}
