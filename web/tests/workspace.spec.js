import path from "node:path";

import { expect, test } from "@playwright/test";


const screenshotRoot = process.env.RCN_SCREENSHOT_DIR;


async function expectNoPageOverflow(page) {
  const dimensions = await page.evaluate(() => ({
    viewport: window.innerWidth,
    page: document.documentElement.scrollWidth,
  }));
  expect(dimensions.page).toBeLessThanOrEqual(dimensions.viewport + 1);
}

async function machineFixtures(page) {
  const response = await page.request.get("/v1/overview");
  expect(response.ok()).toBeTruthy();
  const overview = await response.json();
  const machines = overview.machines || [];
  return {
    ids: machines.map((machine) => machine.machine_id),
    first: machines[0]?.machine_id,
    second: machines[1]?.machine_id,
    gpu: machines.find((machine) => Number(machine.total_gpus || 0) > 0)?.machine_id,
    cpuOnly: machines.find((machine) => Number(machine.total_gpus || 0) === 0)?.machine_id,
  };
}

async function expectNoInteractiveOverlap(page, selector) {
  const problems = await page.locator(selector).evaluateAll((elements) => {
    const visible = elements.filter((element) => {
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && rect.width > 1 && rect.height > 1;
    });
    const failures = [];
    for (let index = 0; index < visible.length; index += 1) {
      const left = visible[index].getBoundingClientRect();
      if ((visible[index].textContent || "").trim() && visible[index].scrollWidth > visible[index].clientWidth + 1 && getComputedStyle(visible[index]).overflowX === "visible") {
        failures.push(`${visible[index].tagName}.${visible[index].className || "-"}:text-overflow:${(visible[index].textContent || "").trim().slice(0, 80)}`);
      }
      for (let other = index + 1; other < visible.length; other += 1) {
        const right = visible[other].getBoundingClientRect();
        const area = Math.max(0, Math.min(left.right, right.right) - Math.max(left.left, right.left))
          * Math.max(0, Math.min(left.bottom, right.bottom) - Math.max(left.top, right.top));
        if (area > 4 && !visible[index].contains(visible[other]) && !visible[other].contains(visible[index])) {
          failures.push(`${visible[index].tagName}/${visible[other].tagName}:intersection`);
        }
      }
    }
    return failures.slice(0, 20);
  });
  expect(problems).toEqual([]);
}


async function expectStableFleetCells(page) {
  const problems = await page.locator(".fleet-table tbody tr").evaluateAll((rows) => rows.flatMap((row, rowIndex) => {
    const cells = [...row.querySelectorAll(":scope > td")];
    const failures = [];
    for (const [cellIndex, cell] of cells.entries()) {
      const cellRect = cell.getBoundingClientRect();
      if (cell.scrollWidth > cell.clientWidth + 1 && getComputedStyle(cell).overflowX === "visible") {
        failures.push(`row-${rowIndex}-cell-${cellIndex}:horizontal-overflow`);
      }
      for (const summary of cell.querySelectorAll(".resource, .connection, .capacity-summary")) {
        const rect = summary.getBoundingClientRect();
        if (rect.left < cellRect.left - 1 || rect.right > cellRect.right + 1) {
          failures.push(`row-${rowIndex}-cell-${cellIndex}:${summary.className}:outside-cell`);
        }
      }
    }
    return failures;
  }));
  expect(problems).toEqual([]);
}


async function expectReadableMobileFleet(page) {
  const problems = await page.locator(".fleet-table tbody tr").evaluateAll((rows) => rows.flatMap((row, rowIndex) => {
    const failures = [];
    const machineName = row.querySelector(".row-primary b");
    if (machineName) {
      const style = getComputedStyle(machineName);
      const rect = machineName.getBoundingClientRect();
      if (style.whiteSpace !== "nowrap" || rect.width < 120) failures.push(`row-${rowIndex}:machine-name-wraps`);
    }
    for (const cellIndex of [3, 4, 5]) {
      const cell = row.children[cellIndex];
      if (!cell || getComputedStyle(cell).display === "none") continue;
      const rect = cell.getBoundingClientRect();
      if (rect.width < 80) failures.push(`row-${rowIndex}-cell-${cellIndex}:too-narrow-${Math.round(rect.width)}`);
      const resource = cell.querySelector(".resource");
      if (resource && resource.getBoundingClientRect().width < 75) failures.push(`row-${rowIndex}-cell-${cellIndex}:resource-unreadable`);
    }
    return failures;
  }));
  expect(problems).toEqual([]);
}


test("public help is directly usable", async ({ page }, testInfo) => {
  await page.goto("/help/overview");
  await expect(page).toHaveURL(/\/help$/);
  await expect(page.getByRole("heading", { name: "帮助与运行手册" })).toBeVisible();
  const architectureLink = page.getByRole("link").filter({ hasText: "架构与边界" }).first();
  await expect(architectureLink).toBeVisible();
  await expect(page.getByRole("link", { name: /帮助首页/ })).toBeVisible();
  await architectureLink.click();
  await expect(page.getByRole("heading", { name: "架构与边界" })).toBeVisible();
  await expect(page.getByText("文档来源")).toBeVisible();
  await expectNoPageOverflow(page);
  await expectNoInteractiveOverlap(page, ".fleet-table tbody tr:first-child td, .fleet-table tbody tr:first-child .resource");
  if (screenshotRoot) {
    await page.screenshot({ path: path.join(screenshotRoot, `help-${testInfo.project.name}.png`), fullPage: true });
  }
});

test("help home search, recent reading and lifecycle process stay coherent", async ({ page }, testInfo) => {
  await page.goto("/help");
  await expect(page.getByRole("heading", { name: "帮助与运行手册" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "角色 Runbook" })).toBeVisible();
  const search = page.getByRole("textbox", { name: "搜索帮助文档" });
  await search.fill("ETA");
  const searchResult = page.locator(".help-results").getByRole("link", { name: /任务生命周期/ });
  await expect(searchResult).toBeVisible();
  await searchResult.click();
  await expect(page.locator(".help-process > div > div")).toHaveCount(7);
  await expect(page.getByText("说明性流程，不代表当前生产状态")).toBeVisible();
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `help-lifecycle-${testInfo.project.name}.png`), fullPage: true });
  await page.getByRole("link", { name: /帮助首页/ }).click();
  await expect(page.getByRole("heading", { name: "最近阅读" })).toBeVisible();
  await expect(page.locator(".help-recent").getByRole("link", { name: /任务生命周期/ })).toBeVisible();
  await expectNoPageOverflow(page);
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `help-home-${testInfo.project.name}.png`), fullPage: true });
});

test("authenticated role runbook uses the shared article shell", async ({ page }) => {
  await page.goto("/help/admin-runbook");
  await expect(page.getByRole("heading", { name: "管理员 Runbook" })).toBeVisible();
  await expect(page.getByText("文档来源")).toBeVisible();
  await expect(page.getByRole("button", { name: /返回运营台/ })).toBeVisible();
  await expectNoPageOverflow(page);
});

test("help loading failure is explicit and retryable", async ({ page }) => {
  const publicResponse = await page.request.get("/v1/help/public");
  expect(publicResponse.ok()).toBeTruthy();
  const publicArticles = await publicResponse.json();
  let attempts = 0;
  await page.route("**/v1/help/public", async (route) => {
    attempts += 1;
    if (attempts === 1) await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "temporary help failure" }) });
    else await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(publicArticles) });
  });
  await page.goto("/help");
  await expect(page.getByRole("heading", { name: "帮助中心暂时不可用" })).toBeVisible();
  await expect(page.getByText("temporary help failure")).toBeVisible();
  await page.getByRole("button", { name: "重试" }).click();
  await expect(page.getByRole("heading", { name: "帮助与运行手册" })).toBeVisible();
});

test("complex operations expose contextual help without losing the current page", async ({ page }, testInfo) => {
  await page.goto("/app/fleet?q=office");
  await expect(page.getByRole("heading", { name: "机器集群" })).toBeVisible();
  const helpButton = page.getByRole("button", { name: /机器连接与执行状态/ });
  await helpButton.click();
  await expect(page.getByRole("dialog", { name: "机器连接与执行状态" })).toBeVisible();
  await expect(page.locator(".help-drawer .icon-button")).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(page.getByRole("link", { name: /打开完整文章/ })).toBeFocused();
  await expect(page.getByRole("link", { name: /打开完整文章/ })).toHaveAttribute("href", "/app/help/architecture");
  await page.keyboard.press("Tab");
  await expect(page.locator(".help-drawer .icon-button")).toBeFocused();
  await expect(page).toHaveURL(/\/app\/fleet\?q=office/);
  await expectNoPageOverflow(page);
  if (screenshotRoot) {
    await page.screenshot({ path: path.join(screenshotRoot, `context-help-${testInfo.project.name}.png`), fullPage: true });
  }
  await page.locator(".help-drawer .icon-button").click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(helpButton).toBeFocused();
  await helpButton.click();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(helpButton).toBeFocused();
});

test("direct app help stays embedded and returns to the Fleet fallback", async ({ page }, testInfo) => {
  await page.goto("/app/help");
  await expect(page).toHaveURL(/\/app\/help$/);
  if (testInfo.project.name === "mobile") await expect(page.locator(".app-nav")).toBeAttached();
  else await expect(page.locator(".app-nav")).toBeVisible();
  await expect(page.locator(".connection")).toBeVisible();
  await expect(page.getByRole("heading", { name: "帮助与运行手册" })).toBeVisible();
  await page.getByRole("button", { name: /返回此前页面/ }).click();
  await expect(page).toHaveURL(/\/app\/fleet$/);
  await expect(page.getByRole("heading", { name: "机器集群" })).toBeVisible();
});

test("embedded help preserves the app shell and returns to the operation query and scroll", async ({ page }) => {
  await page.goto("/app/fleet?q=office");
  await expect(page.getByRole("heading", { name: "机器集群" })).toBeVisible();
  await page.locator(".connection").evaluate((element) => { window.__rcnConnectionNode = element; });
  const expectedScroll = await page.evaluate(() => {
    window.scrollTo({ top: Math.min(240, document.documentElement.scrollHeight - window.innerHeight) });
    return window.scrollY;
  });
  await page.getByTitle("帮助与文档").click();
  await expect(page).toHaveURL(/\/app\/help$/);
  await expect(page.locator(".connection").evaluate((element) => element === window.__rcnConnectionNode)).resolves.toBe(true);
  await page.getByRole("link").filter({ hasText: "架构与边界" }).first().click();
  await expect(page).toHaveURL(/\/app\/help\/architecture$/);
  await page.getByRole("button", { name: /返回此前页面/ }).click();
  await expect(page).toHaveURL(/\/app\/fleet\?q=office$/);
  await expect(page.getByRole("heading", { name: "机器集群" })).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(expectedScroll);
});

test("connect help is the only header action and returns without persisting its token draft", async ({ page }) => {
  await page.goto("/connect");
  const header = page.locator(".public-header");
  await expect(header.getByRole("link", { name: "帮助中心" })).toBeVisible();
  await expect(header.getByRole("link", { name: /连接运营台/ })).toHaveCount(0);
  const tokenInput = page.getByLabel("个人访问 token");
  await tokenInput.fill("unsubmitted-token-draft");
  await header.getByRole("link", { name: "帮助中心" }).click();
  await expect(page).toHaveURL(/\/help$/);
  await expect(page.getByRole("button", { name: /返回连接运营台/ })).toBeVisible();
  await page.getByRole("button", { name: /返回连接运营台/ }).click();
  await expect(page).toHaveURL(/\/connect$/);
  await expect(page.getByLabel("个人访问 token")).toHaveValue("");
  const stored = await page.evaluate(() => ({ token: sessionStorage.getItem("rcn-token"), returnTarget: sessionStorage.getItem("rcn-help-return") }));
  expect(stored).toEqual({ token: null, returnTarget: null });
});

test("unauthenticated app help returns to connect instead of exposing the app shell", async ({ page }) => {
  await page.route("**/v1/overview", (route) => route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ detail: "authentication required" }) }));
  await page.goto("/app/help");
  await expect(page).toHaveURL(/\/connect$/);
  await expect(page.getByRole("heading", { name: "连接计算网络" })).toBeVisible();
});

test("locked role runbooks expose safe metadata without article links", async ({ page }) => {
  const publicResponse = await page.request.get("/v1/help/public");
  expect(publicResponse.ok()).toBeTruthy();
  const publicArticles = await publicResponse.json();
  await page.route("**/v1/help/catalog", async (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      public: publicArticles,
      protected: [{
        slug: "admin-runbook",
        title: "管理员 Runbook",
        summary: "处理 reconcile、机器准入、审计和正式状态切换。",
        audience: "protected",
        category: "role",
        section: "角色 Runbook",
        order: 130,
        access: "locked",
        required_roles: ["admin"],
      }],
    }),
  }));
  await page.goto("/help");
  const locked = page.locator(".help-role.locked", { hasText: "管理员 Runbook" });
  await expect(locked).toContainText("需要 admin 角色");
  await expect(page.getByRole("link", { name: /管理员 Runbook/ })).toHaveCount(0);
  await expectNoPageOverflow(page);
});


test("projects page explains member limits and reveals owner self-service controls", async ({ page }, testInfo) => {
  let identity = {
    actor_id: "member-viewer",
    display_name: "Member Viewer",
    roles: ["member"],
  };
  const project = {
    project_id: "declared-study",
    owner_user_id: "member-owner",
    authorized_user_ids: ["member-viewer"],
    approved: true,
    status: "active",
    allowed_profiles: ["workbench-comsol-study-v1"],
    max_queued_units: 2000,
    max_running_units: 4,
    priority_ceiling: 3,
  };
  await page.route("**/v1/me", (route) => route.fulfill({
    status: 200, contentType: "application/json", body: JSON.stringify(identity),
  }));
  await page.route("**/v1/projects", (route) => route.fulfill({
    status: 200, contentType: "application/json", body: JSON.stringify([project]),
  }));
  await page.route("**/v1/project-registrations", (route) => route.fulfill({
    status: 200, contentType: "application/json", body: "[]",
  }));
  await page.route("**/v1/profiles", (route) => route.fulfill({
    status: 200, contentType: "application/json", body: JSON.stringify([{
      profile_id: "workbench-comsol-study-v1", version: "1.0", output_contracts: [],
    }]),
  }));
  await page.route("**/v1/me/enrollments", (route) => route.fulfill({
    status: 200, contentType: "application/json", body: "[]",
  }));

  await page.goto("/app/projects");
  await expect(page.getByRole("heading", { name: "项目与接入" })).toBeVisible();
  await expect(page.getByText("declared-study", { exact: true })).toBeVisible();
  await expect(page.getByText("机器接入能力已经提供，但你的账号缺少 machine_owner 角色。")).toBeVisible();
  await expect(page.getByRole("button", { name: /生成 30 分钟准入码/ })).toHaveCount(0);
  await expect(page.getByLabel("添加已有用户")).toHaveCount(0);
  await expectNoPageOverflow(page);
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `projects-member-${testInfo.project.name}.png`), fullPage: true });

  identity = {
    actor_id: "member-owner",
    display_name: "Member Owner",
    roles: ["member", "machine_owner"],
  };
  await page.reload();
  await expect(page.getByLabel("添加已有用户")).toBeVisible();
  await expect(page.getByRole("button", { name: /生成 30 分钟准入码/ })).toBeVisible();
  await expect(page.getByText("机器接入能力已经提供，但你的账号缺少 machine_owner 角色。")).toHaveCount(0);
  await expectNoPageOverflow(page);
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `projects-owner-${testInfo.project.name}.png`), fullPage: true });
});


test("fleet route renders dense operational data", async ({ page }, testInfo) => {
  const machines = await machineFixtures(page);
  await page.addInitScript(() => {
    sessionStorage.setItem("rcn-last-event-sequence", "9999999999999999");
  });
  await page.goto("/app/fleet");
  await expect(page.getByRole("heading", { name: "机器集群" })).toBeVisible();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(page.locator(".sync-warning")).toHaveCount(0, { timeout: 10000 });
  await expect(page.locator("tbody tr").first()).toBeVisible();
  await expect(page.locator(".connection small")).toContainText(/最后成功更新/);
  await expect(page.locator(".sync-countdown")).toHaveAttribute("aria-label", /下次同步 \d+ 秒/);
  await expect(page.getByRole("columnheader", { name: "CPU" })).toHaveCount(1);
  await expect(page.getByRole("columnheader", { name: "GPU" })).toHaveCount(1);
  if ((page.viewportSize()?.width || 0) > 1050) {
    await expect(page.getByRole("columnheader", { name: "有效模式 / 管理员覆盖" })).toHaveCount(1);
    const modeAction = page.locator("select[aria-label$='管理员覆盖操作']").first();
    await expect(modeAction).toHaveAttribute("title", /不会直接生效/);
    await expect(modeAction.locator("option")).toContainText(["选择覆盖操作…", "开放：接收新派发", "排空：等待现有任务完成", "暂停：停止新派发"]);
    await expect(page.locator(".mode-hint").first()).toHaveText("变更需预览并确认");
  }
  await expect(page.getByText("未配置 GPU").first()).toBeAttached();
  await expect(page.locator(".resource-gpu:not(.resource-inactive)").first()).toBeAttached();
  const gpuRow = page.locator("tbody tr").filter({ hasText: machines.gpu });
  if (await gpuRow.count()) {
    await expect(gpuRow.locator(".resource-gpu")).not.toHaveClass(/resource-inactive/);
    await expect(gpuRow.locator(".resource-gpu")).toContainText(/NVML|降级/);
    await expect(gpuRow.locator(".resource-gpu")).toHaveAttribute("title", /1 张/);
  }
  const cpuOnlyRow = page.locator("tbody tr").filter({ hasText: machines.cpuOnly });
  if (await cpuOnlyRow.count()) {
    await expect(cpuOnlyRow.locator(".resource-gpu")).toHaveClass(/resource-inactive/);
    await expect(cpuOnlyRow.locator(".resource-gpu")).toContainText("未配置 GPU");
  }
  await expectNoPageOverflow(page);
  await expectStableFleetCells(page);
  if (testInfo.project.name === "mobile") {
    await expectReadableMobileFleet(page);
    await page.locator(".nav-toggle").click();
    await expect(page.getByRole("link", { name: /运营与审计/ })).toBeVisible();
    await page.getByRole("link", { name: /机器集群/ }).click();
  }
  if (screenshotRoot) {
    await page.screenshot({ path: path.join(screenshotRoot, `fleet-${testInfo.project.name}.png`), fullPage: true });
  }
});


test("network map renders registered machine data flow", async ({ page }, testInfo) => {
  const machines = await machineFixtures(page);
  await page.goto("/app/map");
  await expect(page.getByRole("heading", { name: "网络拓扑" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "控制流" })).toBeVisible();
  await expect(page.getByText("Workbench", { exact: true })).toBeVisible();
  await expect(page.getByText("Partition Planner", { exact: true })).toBeVisible();
  await expect(page.getByText("Control Plane", { exact: true })).toBeVisible();
  await expect(page.getByText("Dispatcher", { exact: true })).toBeVisible();
  await expect(page.locator(".topology-machine")).toHaveCount(machines.ids.length);
  for (const machine of machines.ids) {
    await expect(page.locator(".topology-machine").filter({ hasText: machine })).toBeVisible();
  }
  await expect(page.locator(".topology-machine").filter({ hasText: machines.cpuOnly }).getByText("未配置 GPU")).toBeVisible();
  await expect(page.locator(".topology-machine").filter({ hasText: machines.gpu }).locator(".resource-gpu")).toBeVisible();
  await expect(page.getByRole("heading", { name: "结果回流" })).toBeVisible();
  await expect(page.getByText("Origin staging", { exact: true })).toBeVisible();
  await page.locator(".topology-machine").filter({ hasText: machines.first }).click();
  await expect(page).toHaveURL(new RegExp(`/app/machines/${machines.first}`));
  await page.goBack();
  await expect(page.getByRole("heading", { name: "网络拓扑" })).toBeVisible();
  await expectNoPageOverflow(page);
  if (screenshotRoot) {
    await page.screenshot({ path: path.join(screenshotRoot, `network-map-${testInfo.project.name}.png`), fullPage: true });
  }
});


test("fleet deep links, comparison selection, and browser return preserve state", async ({ page }, testInfo) => {
  const machines = await machineFixtures(page);
  await page.goto(`/app/fleet?drawer=${machines.first}&tab=performance&selected=${machines.first},${machines.second}`);
  await expect(page.locator(".drawer").getByRole("heading", { name: machines.first })).toBeVisible();
  await expect(page.getByText("已选择 2 台")).toBeVisible();
  await expect(page.getByRole("spinbutton", { name: "批量目标并发" })).toBeVisible();
  await page.locator(".drawer").getByRole("button", { name: "关闭" }).click();
  await page.getByRole("link", { name: /对比/ }).click();
  await expect(page.getByRole("heading", { name: "多机对比" })).toBeVisible();
  await expect(page.locator(".compare-summary article")).toHaveCount(2);
  await expect(page.locator(".comparison-chart")).toHaveCount(4);
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `compare-${testInfo.project.name}.png`), fullPage: true });
  await page.goBack();
  await expect(page).toHaveURL(new RegExp(`selected=${machines.first}%2C${machines.second}`));
  await expectNoPageOverflow(page);
});


test("batch machine control reaches a real server preview without confirming", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "stateful preview is covered once on desktop");
  const machines = await machineFixtures(page);
  await page.goto(`/app/fleet?selected=${machines.first},${machines.second}`);
  await page.locator(".batch-bar").getByRole("button", { name: "排空", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "批量排空" })).toBeVisible();
  await page.getByRole("button", { name: "生成预览" }).click();
  await expect(page.locator(".ticket-summary")).toContainText("machine-control");
  await expect(page.locator(".impact-grid article")).toHaveCount(2);
  await expect(page.getByRole("button", { name: "确认执行" })).toBeVisible();
  await page.locator(".control-dialog > header .icon-button").click();
});


test("machine, job, control, alert, and admin deep pages render real records", async ({ page }, testInfo) => {
  const machines = await machineFixtures(page);
  await page.goto(`/app/machines/${machines.first}?tab=performance&window=6h`);
  await expect(page.getByRole("heading", { name: machines.first })).toBeVisible();
  const capacity = page.locator(".detail-capacity strong");
  await expect(capacity).toBeVisible();
  await expect(capacity).toHaveCSS("white-space", "nowrap");
  const capacityLayout = await capacity.evaluate((element) => ({
    scrollWidth: element.scrollWidth,
    clientWidth: element.clientWidth,
    gridColumns: getComputedStyle(element.closest(".detail-title")).gridTemplateColumns,
  }));
  expect(capacityLayout.scrollWidth).toBeLessThanOrEqual(capacityLayout.clientWidth + 1);
  const expectedTitleColumns = (page.viewportSize()?.width || 0) <= 680 ? 2 : 4;
  expect(capacityLayout.gridColumns.split(" ")).toHaveLength(expectedTitleColumns);
  await expect(page.getByText(/当前策略：CPU/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "缺失与 stale 区间" })).toBeVisible();
  await expect(page.locator(".chart-panel")).toHaveCount(6);
  await expectNoPageOverflow(page);
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `machine-detail-${testInfo.project.name}.png`), fullPage: true });

  await page.goto("/app/runs");
  const jobsResponse = await page.request.get("/v1/jobs?view=summary");
  expect(jobsResponse.ok()).toBeTruthy();
  const jobs = await jobsResponse.json();
  expect(jobs.length).toBeGreaterThan(0);
  // Runs must expose completed Workbench submissions by default; short jobs
  // should not disappear merely because they finished before the page opened.
  await expect(page.locator(".filter-row select")).toHaveValue("all");
  await expect(page.getByText("已加载全部可见 Job")).toBeVisible();
  await page.goto(`/app/runs/${jobs[0].job_id}`);
  await expect(page.getByRole("heading", { name: "WorkUnit 与 attempt" })).toBeVisible();

  await page.goto("/app/control");
  await expect(page.getByRole("heading", { name: "控制中心" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Dispatcher" })).toBeVisible();
  await page.goto("/app/alerts");
  await expect(page.getByRole("heading", { name: "告警中心" })).toBeVisible();
  await page.goto("/app/admin?tab=nodes");
  await expect(page.getByRole("heading", { name: "管理员面板" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "节点准入与运行时" })).toBeVisible();
  await expect(page.locator(".runtime-grid article")).toHaveCount(machines.ids.length);
  await expectNoPageOverflow(page);
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `admin-nodes-${testInfo.project.name}.png`), fullPage: true });
});


test("machine scheduling and daily execution settings are visible without overflow", async ({ page }, testInfo) => {
  const machines = await machineFixtures(page);
  await page.route("**/v1/profiles", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 850));
    await route.continue();
  });
  await page.goto(`/app/machines/${machines.first}?tab=config`);
  await expect(page.getByRole("button", { name: "配置" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "运行时段" })).toBeVisible();
  await expect(page.getByLabel("不限制运行时段")).toBeVisible();
  await expect(page.getByLabel("调度时区")).toBeVisible();
  await expect(page.getByRole("heading", { name: "机器所有者策略" })).toBeVisible();
  await expect(page.getByLabel("所有者模式")).toBeVisible();
  await expect(page.getByLabel("键鼠空闲门槛")).toBeVisible();
  await expect(page.getByRole("heading", { name: "执行调优" })).toBeVisible();
  await expect(page.getByText("Profile 并发上限", { exact: true })).toBeVisible();
  await expect(page.getByRole("status", { name: "正在读取 Profile 并发配置" })).toBeVisible();
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `machine-settings-loading-${testInfo.project.name}.png`), fullPage: true });
  await expect(page.getByRole("status", { name: "正在读取 Profile 并发配置" })).toBeHidden();
  await expect(page.getByRole("heading", { name: "受控执行状态" })).toBeVisible();
  await expectNoPageOverflow(page);
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `machine-settings-${testInfo.project.name}.png`), fullPage: true });
});


test("job placement diagnostics distinguish loading from an empty result", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "diagnostic delay injection is covered once");
  const response = await page.request.get("/v1/jobs?limit=200&view=compact");
  expect(response.ok()).toBeTruthy();
  const jobs = await response.json();
  const source = jobs.find((job) => (job.work_units || []).length > 0);
  test.skip(!source, "candidate has no job with work units");
  const unit = source.work_units[0];
  const queuedUnit = { ...unit, status: "queued", dispatch_phase: "queued", assigned_machine_id: null };
  const queuedJob = { ...source, status: "queued", activity_state: "queued", work_units: [queuedUnit, ...source.work_units.slice(1)] };
  await page.route("**/v1/jobs?limit=200&view=compact", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(jobs.map((job) => job.job_id === source.job_id ? queuedJob : job)),
  }));
  let releaseDiagnostics;
  const diagnosticsGate = new Promise((resolve) => { releaseDiagnostics = resolve; });
  await page.route(`**/v1/jobs/${source.job_id}/placement-diagnostics`, async (route) => {
    await diagnosticsGate;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ units: [{ ...queuedUnit, ordinal: queuedUnit.ordinal || 0, eligible_machine_count: 0, queue_position: 1, blockers: [] }] }),
    });
  });

  await page.goto(`/app/runs?drawer=${source.job_id}`);
  await expect(page.getByRole("status", { name: "正在计算放置条件" })).toBeVisible();
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, "job-placement-loading-desktop.png"), fullPage: true });
  releaseDiagnostics();
  await expect(page.getByRole("status", { name: "正在计算放置条件" })).toBeHidden();
  await expect(page.locator(".placement-diagnostics article")).toHaveCount(1);
  await expectNoPageOverflow(page);
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, "job-placement-loaded-desktop.png"), fullPage: true });
});


test("control operation deep link renders persisted stages", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "candidate control record is created once");
  const machines = await machineFixtures(page);
  const previewResponse = await page.request.post("/v1/admin/machine-controls/preview", {
    data: { action: "set_admin_mode", targets: [{ machine_id: machines.first, requested_mode: "drain" }], reason: "candidate browser deep-link verification" },
  });
  expect(previewResponse.ok()).toBeTruthy();
  const ticket = await previewResponse.json();
  const confirmResponse = await page.request.post("/v1/admin/machine-controls/confirm", {
    data: { ticket_id: ticket.ticket_id, confirmation_hash: ticket.confirmation_hash },
  });
  expect(confirmResponse.ok()).toBeTruthy();
  const run = await confirmResponse.json();
  await page.goto(`/app/control/${run.operation_id}`);
  await expect(page.getByRole("heading", { name: "控制操作详情" })).toBeVisible();
  await expect(page.getByText(run.operation_id, { exact: true })).toBeVisible();
  await expect(page.locator(".operation-stages .done")).toHaveCount(4);
  await expect(page.getByRole("link", { name: machines.first })).toBeVisible();
  await expectNoPageOverflow(page);
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `control-operation-${testInfo.project.name}.png`), fullPage: true });

  const clearPreview = await page.request.post("/v1/admin/machine-controls/preview", {
    data: { action: "clear_admin_mode", targets: [{ machine_id: machines.first }], reason: "" },
  });
  const clearTicket = await clearPreview.json();
  const clearConfirm = await page.request.post("/v1/admin/machine-controls/confirm", {
    data: { ticket_id: clearTicket.ticket_id, confirmation_hash: clearTicket.confirmation_hash },
  });
  expect(clearConfirm.ok()).toBeTruthy();
});


test("administrator forms submit through the candidate API", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "stateful candidate forms are exercised once");
  await page.goto("/app/admin?tab=users");
  await page.getByLabel("用户 ID").fill("playwright-admin-080");
  await page.getByLabel("显示名称").fill("Playwright Admin Fixture");
  await page.getByRole("button", { name: "保存用户" }).click();
  await expect(page.locator(".admin-table > div").filter({ hasText: "Playwright Admin Fixture" })).toBeVisible();

  await page.getByRole("button", { name: /项目授权/ }).click();
  await page.getByLabel("项目 ID").fill("playwright-project-080");
  await page.getByLabel("所有者", { exact: true }).fill("playwright-admin-080");
  await page.getByLabel("允许 Profile").fill("workbench-comsol-scan-v1");
  await page.getByRole("button", { name: "保存项目" }).click();
  const projectRow = page.locator(".projects-table > div").filter({ hasText: "playwright-project-080" }).first();
  await expect(projectRow).toBeVisible();
  await projectRow.getByRole("button", { name: "冻结" }).click();
  await expect(page.locator(".inline-success")).toContainText("项目已冻结");
  await expect(projectRow.getByRole("button", { name: "恢复" })).toBeVisible();
  await projectRow.getByRole("button", { name: "恢复" }).click();
  await expect(page.locator(".inline-success")).toContainText("项目已恢复");

  await page.getByRole("button", { name: /Profile 版本/ }).click();
  await page.getByLabel("Profile ID").fill("playwright-profile-080");
  await page.getByLabel("版本", { exact: true }).fill("0.8.0");
  await page.getByLabel("输出契约").fill("playwright-output-080");
  await page.getByRole("button", { name: "创建新版本" }).click();
  await expect(page.getByRole("heading", { name: "playwright-profile-080" })).toBeVisible();

  await page.getByRole("button", { name: /Solver 审批/ }).click();
  await page.getByLabel("项目", { exact: true }).fill("playwright-project-080");
  await page.getByLabel("模板 SHA-256").fill("a".repeat(64));
  await page.getByLabel("模板角色").fill("playwright-template-role");
  await page.getByRole("button", { name: "签发审批" }).click();
  const approval = page.locator(".approval-list article")
    .filter({ hasText: "playwright-project-080" })
    .filter({ has: page.getByRole("button", { name: "撤销" }) })
    .first();
  await expect(approval).toBeVisible();
  await approval.getByRole("button", { name: "撤销" }).click();
  await expect(page.locator(".inline-success")).toContainText("已撤销");
});


test("administrator tabs remain usable without page overflow", async ({ page }, testInfo) => {
  const recentJobs = Array.from({ length: 8 }, (_, index) => ({ job_id: `job-layout-evidence-${String(index + 1).padStart(2, "0")}`, warnings: index % 3 === 0 ? ["template hash observed"] : [] }));
  await page.route("**/v1/admin/template-environments", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify([
      { approval: { approval_id: "approval-layout-1", project_id: "demo-eigen-study", template_role: "demo_eigen", active: false, template_hash_policy: "warn_on_change", allowed_study_kinds: ["eigenfrequency"], template_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, observed_template_hashes: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], observed_study_kinds: ["eigenfrequency"], output_contracts: ["eigenfrequency-table", "mode-shape"], recent_jobs: recentJobs },
      { approval: { approval_id: "approval-layout-2", project_id: "demo-frequency-study", template_role: "demo_spectrum", active: true, template_hash_policy: "warn_on_change", allowed_study_kinds: ["frequency_domain"], template_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }, observed_template_hashes: [], observed_study_kinds: ["frequency_domain"], output_contracts: [], recent_jobs: [] },
    ]),
  }));
  await page.goto("/app/admin?tab=users");
  await expect(page.locator(".page-actions .context-help")).toHaveCount(0);
  await expect(page.locator(".admin-guide .context-help")).toHaveCount(1);
  await expect(page.getByRole("button", { name: /管理员面板总览/ })).toBeVisible();
  for (const [name, slug, helpName] of [["用户与 Token", "users", "用户、角色与个人 Token"], ["项目授权", "projects", "项目授权与运行配额"], ["Profile 版本", "profiles", "不可变 Profile 版本"], ["Solver 审批", "approvals", "Solver Compatibility Approval"], ["模板环境", "templates", "受信任模板环境"], ["节点与运行时", "nodes", "节点准入与正式 Runtime"]]) {
    await page.getByRole("button", { name: new RegExp(name) }).click();
    await expect(page.locator(".admin-tab-guide .context-help")).toHaveCount(1);
    await expect(page.getByRole("button", { name: new RegExp(helpName) })).toBeVisible();
    await expectNoPageOverflow(page);
    if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `admin-${slug}-${testInfo.project.name}.png`), fullPage: true });
  }
  await page.getByRole("button", { name: /容量策略/ }).click();
  await expect(page.locator(".admin-tab-guide .context-help")).toHaveCount(1);
  await expect(page.getByRole("button", { name: /容量策略与资源自治/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "资源边界" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "自适应证据与安全余量" })).toBeVisible();
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `admin-capacity-${testInfo.project.name}.png`), fullPage: true });
  if (testInfo.project.name === "desktop") {
    await page.locator(".admin-tab-guide .context-help").click();
    await expect(page.getByRole("dialog", { name: "容量策略与资源自治" })).toBeVisible();
    await expect(page.getByText("本页重点")).toBeVisible();
    if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, "admin-capacity-help-desktop.png"), fullPage: true });
    await page.locator(".help-drawer .icon-button").click();
  }
});


test("administrator resources reveal independently with explicit loading and true empty states", async ({ page }, testInfo) => {
  await page.route("**/v1/users", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 650));
    await route.continue();
  });
  await page.route("**/v1/admin/template-environments", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 2600));
    await route.continue();
  });

  await page.goto("/app/admin?tab=users");
  await expect(page.getByRole("status", { name: "正在加载用户与角色" })).toBeVisible();
  await expect(page.locator(".admin-table > div").nth(1)).toBeVisible();
  await expect(page.getByRole("status", { name: "正在加载用户与角色" })).toBeHidden();

  await page.getByRole("button", { name: /模板环境/ }).click();
  await expect(page.getByRole("status", { name: "正在加载模板环境" })).toBeVisible();
  await expectNoPageOverflow(page);
  if (screenshotRoot) await page.screenshot({ path: path.join(screenshotRoot, `admin-loading-${testInfo.project.name}.png`), fullPage: true });
  await expect(page.getByRole("status", { name: "正在加载模板环境" })).toBeHidden();
});


test("administrator loading failure is explicit and retryable", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "failure injection is covered once");
  let failed = false;
  await page.route("**/v1/users", async (route) => {
    if (!failed) {
      failed = true;
      await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "temporary user directory outage" }) });
      return;
    }
    await route.continue();
  });

  await page.goto("/app/admin?tab=users");
  await expect(page.getByRole("alert")).toContainText("temporary user directory outage");
  await page.getByRole("button", { name: "重试" }).click();
  await expect(page.locator(".admin-table > div").nth(1)).toBeVisible();
  await expect(page.getByRole("alert")).toBeHidden();
});


test("reduced motion keeps the fleet fully usable", async ({ page }, testInfo) => {
  const machines = await machineFixtures(page);
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto(`/app/fleet?drawer=${machines.first}`);
  await expect(page.locator(".drawer")).toBeVisible();
  const animationDuration = await page.locator(".drawer").evaluate((element) => getComputedStyle(element).animationDuration);
  expect(parseFloat(animationDuration || "0")).toBeLessThanOrEqual(0.01);
  await expect(page.getByRole("link", { name: /打开完整详情/ })).toBeVisible();
});


test("fleet density stays non-overlapping across desktop zoom equivalents", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "multi-width density gate runs once");
  // 1440 physical pixels at 100%, 125%, and 150% scaling yields these CSS widths.
  for (const width of [1440, 1152, 960]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/app/fleet");
    await expect(page.locator("tbody tr").first()).toBeVisible();
    await expectNoPageOverflow(page);
    await expectNoInteractiveOverlap(page, ".fleet-table tbody tr td, .fleet-table tbody tr .resource");
    await expectStableFleetCells(page);
  }
});

test("help shell and contextual drawer stay non-overlapping across desktop zoom equivalents", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "multi-width help density gate runs once");
  // 1440 physical pixels at 100%, 125%, and 150% scaling yields these CSS widths.
  for (const width of [1440, 1152, 960]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/help/architecture");
    await expect(page.getByRole("heading", { name: "架构与边界" })).toBeVisible();
    await expectNoPageOverflow(page);
    await expectNoInteractiveOverlap(page, ".help-header > *, .help-layout > *, .help-sources > header, .help-sources > div > div");
    await page.goto("/app/help/architecture");
    await expect(page.getByRole("heading", { name: "架构与边界" })).toBeVisible();
    await expect(page.locator(".app-nav")).toBeVisible();
    await expectNoPageOverflow(page);
    await expectNoInteractiveOverlap(page, ".embedded-help-header > *, .help-layout > *, .help-sources > header, .help-sources > div > div");
    await page.goto("/app/fleet");
    await page.getByRole("button", { name: /机器连接与执行状态/ }).click();
    await expect(page.getByRole("dialog", { name: "机器连接与执行状态" })).toBeVisible();
    await expectNoPageOverflow(page);
    await expectNoInteractiveOverlap(page, ".help-drawer > header > *, .help-drawer > footer > *");
  }
});

test("reduced motion opens contextual help without a slide animation", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "motion style gate runs once");
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/app/fleet");
  await page.getByRole("button", { name: /机器连接与执行状态/ }).click();
  const animationDuration = await page.locator(".help-drawer").evaluate((element) => getComputedStyle(element).animationDuration);
  expect(parseFloat(animationDuration || "0")).toBeLessThanOrEqual(0.01);
  await expect(page.getByRole("dialog", { name: "机器连接与执行状态" })).toBeVisible();
});

test("runs queue cards and unit chips open the owning job drawer", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "interaction gate runs once");
  // Seed a stable active view even after the animated demo has finished.
  // Completed cards intentionally pin their action strip, not this drawer.
  const jobsResponse = await page.request.get("/v1/jobs?limit=200&view=summary");
  expect(jobsResponse.ok()).toBeTruthy();
  const originalJobs = await jobsResponse.json();
  const source = originalJobs.find((job) => (job.work_units || []).length > 0);
  expect(source).toBeTruthy();
  const machines = await machineFixtures(page);
  const jobs = originalJobs.map((job) => job.job_id !== source.job_id ? job : {
    ...job, status: "running", activity_state: "active", activity_phase: "running",
    work_units: job.work_units.map((unit, index) => index ? unit : {
      ...unit, status: "running", dispatch_phase: "running", assigned_machine_id: machines.first,
    }),
  });
  await page.route("**/v1/jobs?limit=200&view=compact", (route) => route.fulfill({ json: jobs }));
  await page.route("**/v1/events/stream", (route) => route.abort());
  await page.goto("/app/runs");
  await expect(page.locator(".queue-board:not(.finished-board)")).toBeVisible();
  const activeCards = page.locator(".queue-jobs .queue-job.clickable:not(.finished-job)");
  await expect(activeCards.first()).toBeVisible();
  await activeCards.first().click();
  await expect(page.locator(".drawer")).toBeVisible();
  expect(new URL(page.url()).searchParams.get("drawer")).toBeTruthy();
  await page.locator(".drawer > header .icon-button[title=关闭]").click();
  await expect(page.locator(".drawer")).toHaveCount(0);
  const chips = page.locator(".machine-lane .unit-chip.clickable");
  await expect(chips.first()).toBeVisible();
  await chips.first().click();
  await expect(page.locator(".drawer")).toBeVisible();
  expect(new URL(page.url()).searchParams.get("unit")).toBeTruthy();
  await expect(page.locator(".timeline-item.unit-highlight")).toHaveCount(1);
});

test("a large completed job paints its scheduler shell immediately and hydrates payload after", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "hydration gate runs once");
  const response = await page.request.get("/v1/jobs?limit=200&view=compact");
  expect(response.ok()).toBeTruthy();
  const jobs = await response.json();
  const target = (jobs || [])
    .filter((job) => (job.completed_unit_count || 0) > 0 && job.updated_at)
    .sort((left, right) => right.updated_at.localeCompare(left.updated_at))[0];
  test.skip(!target, "no completed job available to exercise the detail page");
  await page.goto(`/app/runs/${target.job_id}`);
  // Stage one: the scheduler shell (units without payload bytes) must paint.
  await expect(page.locator(".unit-detail-list article").first()).toBeVisible({ timeout: 15000 });
  // Stage two: the scientific payload hydrates; atom strips come from the
  // full envelope only, so their arrival proves the two-stage hydration ran.
  await expect(page.locator(".atom-strip").first()).toBeVisible({ timeout: 30000 });
  await expectNoPageOverflow(page);
});

test("finished jobs stay on the runs board until dismissed and can be restored", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "retention gate runs once");
  await page.goto("/app/runs");
  await expect(page.locator(".data-section")).toBeVisible();
  const finishedCards = page.locator(".finished-board .queue-jobs .queue-job.finished-job");
  if ((await finishedCards.count()) === 0) {
    test.skip(true, "no finished jobs to exercise board retention");
    return;
  }
  const before = await finishedCards.count();
  // Hover reveals the in-card action strip; clicking the card pins it so the
  // strip survives the pointer leaving the card.
  const firstCard = finishedCards.first();
  await firstCard.hover();
  await expect(firstCard.locator(".finished-actions")).toBeVisible();
  await firstCard.click();
  await expect(firstCard).toHaveClass(/pinned/);
  await page.mouse.move(8, 8);
  await expect(firstCard.locator(".finished-actions")).toBeVisible();
  // Dismiss one card; the dismissal survives a reload.
  await firstCard.locator(".finished-actions .finished-action.danger").click();
  await expect(finishedCards).toHaveCount(before - 1);
  await page.reload();
  await expect(finishedCards).toHaveCount(before - 1);
  // One-key close of everything currently on the board; the removed tray
  // then lists every closed job for single-card or bulk restore.
  if (before > 1) {
    await page.getByRole("button", { name: /一键关闭/ }).click();
  }
  await expect(finishedCards).toHaveCount(0);
  const trayHead = page.locator(".removed-tray-head");
  await expect(trayHead).toBeVisible();
  await trayHead.click();
  const removedRows = page.locator(".removed-list .removed-row:not(.removed-row-all)");
  await expect(removedRows).toHaveCount(before);
  // The bulk action row exists only with multiple removed Jobs; it is not
  // another Job and must not inflate the per-card count.
  await expect(page.locator(".removed-list .removed-row-all")).toHaveCount(before > 1 ? 1 : 0);
  // Single-card restore: exactly one card returns, the tray keeps the rest.
  await removedRows.first().locator("button", { hasText: "找回" }).click();
  await expect(finishedCards).toHaveCount(1);
  await expect(removedRows).toHaveCount(before - 1);
  if (before > 2) {
    await page.locator(".removed-list .removed-row-all button").click();
  } else if (before === 2) {
    await removedRows.first().locator("button", { hasText: "找回" }).click();
  }
  await expect(finishedCards).toHaveCount(before);
});
