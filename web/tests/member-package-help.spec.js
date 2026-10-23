import path from "node:path";
import { expect, test } from "@playwright/test";
import { memberApiFixture } from "./member-client.fixture";

const guideSlug = "member-task-package";

async function packagedHelpFixture(page, { online = true } = {}) {
  // Read the test server's actual packaged public article, then use read-only
  // browser fixtures. No center, login, submission, or compute operation runs.
  await page.request.get("/local/v1/capabilities");
  const index = await page.request.get("/v1/help/public");
  expect(index.ok()).toBeTruthy();
  const publicArticles = await index.json();
  const guide = publicArticles.find((article) => article.slug === guideSlug);
  expect(guide).toBeTruthy();
  const response = await page.request.get(`/v1/help/public/${guideSlug}`);
  expect(response.ok()).toBeTruthy();
  const article = await response.json();
  const sharingResponse = await page.request.get("/v1/help/public/getting-started");
  expect(sharingResponse.ok()).toBeTruthy();
  const sharingArticle = await sharingResponse.json();
  const member = await memberApiFixture(page, { online });
  const helpCalls = [];
  await page.route(/^https?:\/\/[^/]+\/v1\//, async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    helpCalls.push({ pathname, method: request.method(), headers: request.headers() });
    if (pathname === "/v1/help/public") return route.fulfill({ json: publicArticles });
    if (pathname === "/v1/help/catalog") return route.fulfill({ json: { public: publicArticles, protected: [] } });
    if (pathname === `/v1/help/public/${guideSlug}`) return route.fulfill({ json: article });
    if (pathname === "/v1/help/public/getting-started") return route.fulfill({ json: sharingArticle });
    return route.fulfill({ status: 404, json: { detail: "fixture route unavailable" } });
  });
  return { ...member, guide, sharingArticle, helpCalls };
}

async function expectNoOverflow(page) {
  const layout = await page.evaluate(() => ({
    width: innerWidth,
    scrollWidth: document.documentElement.scrollWidth,
    overflowing: [...document.querySelectorAll(".help-main, .help-article, .markdown, .markdown pre, .help-process, .help-sources")]
      .map((element) => ({ className: element.className, tag: element.tagName,
        width: element.getBoundingClientRect().width, right: element.getBoundingClientRect().right,
        scrollWidth: element.scrollWidth })),
  }));
  expect(layout.scrollWidth, JSON.stringify(layout)).toBeLessThanOrEqual(layout.width + 1);
}

async function screenshot(page, testInfo, name) {
  if (process.env.RCN_SCREENSHOT_DIR) await page.screenshot({
    path: path.join(process.env.RCN_SCREENSHOT_DIR, `${name}-${testInfo.project.name}.png`), fullPage: true,
  });
}

test("visible package preparation entry opens installed Agent guide and returns to submit", async ({ page }, testInfo) => {
  const fixture = await packagedHelpFixture(page);
  await page.goto("/app/submit");
  const importPanel = page.locator(".member-import");
  const entry = importPanel.getByRole("link", { name: "如何准备任务包", exact: true });
  await expect(entry).toBeVisible();
  await expect(entry).toHaveAttribute("href", `/app/help/${guideSlug}`);
  await expect(importPanel).toContainText("让本机 Agent 按指南准备");
  await expect(page.getByLabel("选择任务包", { exact: true })).toBeEnabled();
  await expectNoOverflow(page);
  await screenshot(page, testInfo, "member-package-entry");
  await entry.click();
  await expect(page).toHaveURL(new RegExp(`/app/help/${guideSlug}$`));
  await expect(page.getByRole("heading", { level: 1, name: fixture.guide.title })).toBeVisible();
  await expect(page.locator(".help-article .markdown")).toContainText("Agent");
  await expect(page.locator(".help-article .markdown").getByRole("heading", { name: "把这段交给本机 Agent", level: 2 })).toBeVisible();
  await expect(page.locator(".help-sources")).toContainText("docs/member-task-package-guide.zh.md");
  await screenshot(page, testInfo, "member-package-guide");
  await expectNoOverflow(page);
  await page.getByRole("button", { name: "返回此前页面", exact: true }).click();
  await expect(page).toHaveURL(/\/app\/submit$/);
  await expect(entry).toBeVisible();
  expect(fixture.calls.every((call) => call.method === "GET")).toBe(true);
  expect(fixture.helpCalls.every((call) => call.method === "GET" && !call.headers.authorization)).toBe(true);
  expect(fixture.jobsCreated()).toBe(0);
});

test("public links inside package guide preserve the destination article in member client", async ({ page }) => {
  const fixture = await packagedHelpFixture(page);
  await page.goto(`/app/help/${guideSlug}`);
  await page.locator(".help-article .markdown").getByRole("link", { name: "开始使用", exact: true }).click();
  await expect(page).toHaveURL(/\/app\/help\/getting-started$/);
  await expect(page.getByRole("heading", { level: 1, name: fixture.sharingArticle.title })).toBeVisible();
  await page.goto("/help/member-task-package?from=guide#agent");
  await expect(page).toHaveURL(/\/app\/help\/member-task-package\?from=guide#agent$/);
  await expect(page.getByRole("heading", { level: 1, name: fixture.guide.title })).toBeVisible();
});

test("offline member can find package preparation guide through help search", async ({ page }) => {
  const fixture = await packagedHelpFixture(page, { online: false });
  await page.goto("/app/submit");
  await expect(page.getByText("当前离线，保留本机身份与提交记录。")).toBeVisible();
  await page.getByRole("link", { name: "如何准备任务包", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: fixture.guide.title })).toBeVisible();
  await page.goto("/app/help");
  await page.getByRole("textbox", { name: "搜索帮助文档" }).fill("任务包");
  const result = page.locator(".help-results").getByRole("link").filter({ hasText: fixture.guide.title });
  await expect(result).toBeVisible();
  await result.click();
  await expect(page).toHaveURL(new RegExp(`/app/help/${guideSlug}$`));
  await expect(page.locator(".help-sources")).toContainText("docs/member-task-package-guide.zh.md");
  await expect(page.locator(".help-nav-locked")).toHaveCount(0);
  await expectNoOverflow(page);
  expect(fixture.calls.every((call) => call.method === "GET")).toBe(true);
  expect(fixture.helpCalls.some((call) => call.pathname.startsWith("/v1/help/protected"))).toBe(false);
});
