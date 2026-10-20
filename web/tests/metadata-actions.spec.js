import { build } from "esbuild";
import { expect, test } from "@playwright/test";

let bundle;
test.beforeAll(async () => {
  bundle = (await build({ entryPoints: ["src/main.jsx"], bundle: true, write: false, outdir: "ignored-in-memory",
    jsx: "automatic", define: { "process.env.NODE_ENV": '"production"' } })).outputFiles;
});

async function fixture(page, options = {}) {
  const state = { actor: "admin-one", roles: ["admin", "member"], calls: [], receipts: new Map(), recoveryOffline: false,
    dropReply: false, wrongReceipt: false, recoveryDenied: false, reject: false,
    user: { user_id: "alice", display_name: "Alice", roles: ["member"], active: true }, ...options };
  await page.route("**/*", async (route) => {
    const request = route.request(), url = new URL(request.url());
    const json = (value, status = 200) => route.fulfill({ status, json: value });
    state.calls.push({ path: url.pathname, method: request.method(), body: request.postData(), id: request.headers()["x-rcn-request-id"] });
    if (url.pathname === "/bundle.js" || url.pathname === "/bundle.css") return route.fulfill({ contentType: url.pathname.endsWith("js") ? "application/javascript" : "text/css", body: bundle.find((file) => file.path.endsWith(url.pathname.endsWith("js") ? ".js" : ".css")).text });
    if (url.pathname === "/local/v1/capabilities") return json({}, 404);
    if (url.pathname === "/v1/events/stream") return route.abort();
    if (url.pathname === "/v1/me") return json({ actor_id: state.actor, roles: state.roles });
    if (url.pathname === "/v1/overview") return json({ generated_at: new Date().toISOString(), machines: [], policies: {}, summary: {} });
    if (url.pathname === "/v1/settings/features") return json({ visibility: "full" });
    if (url.pathname === "/v1/users") return json([state.user]);
    if (url.pathname === "/v1/profiles") return json([]);
    if (url.pathname === "/v1/admin/people/alice/submission-policy") return json({ person_id: "alice", policy: null, usage: {} });
    if (url.pathname === "/v1/admin/break-glass") return json({ configured: true });
    if (url.pathname === "/v1/users/alice" && request.method() === "PUT" || url.pathname === "/v1/admin/break-glass/pin" && request.method() === "PUT") {
      if (state.reject) { state.reject = false; return json({ detail: "state conflict" }, 409); }
      const kind = url.pathname.endsWith("/pin") ? "break_glass_pin" : "user_update";
      const result = kind === "break_glass_pin" ? { configured: true, updated_at: "2026-10-17T12:00:00Z" } : structuredClone(request.postDataJSON());
      if (kind === "user_update") state.user = structuredClone(result);
      const id = request.headers()["x-rcn-request-id"];
      expect(id).toMatch(/^[0-9a-f-]{36}$/);
      state.receipts.set(id, { request_id: id, kind, subject_id: kind === "user_update" ? "alice" : "global", state: "completed", result });
      if (state.dropReply) { state.dropReply = false; return route.abort(); }
      await new Promise((resolve) => setTimeout(resolve, 80));
      if (state.incompleteReply) { state.incompleteReply = false; return json({}); }
      return json(result);
    }
    if (url.pathname.startsWith("/v1/metadata-operations/")) {
      if (state.recoveryDenied) return json({ detail: "permission revoked" }, 403);
      if (state.recoveryOffline) return json({ detail: "receipt offline" }, 503);
      const receipt = state.receipts.get(decodeURIComponent(url.pathname.split("/").at(-1)));
      return receipt ? json(state.wrongReceipt ? { ...receipt, subject_id: "another-person" } : state.incompleteReceipt ? { ...receipt, result: null } : receipt) : json({ detail: "not found" }, 404);
    }
    if (url.pathname.startsWith("/v1/")) return json([]);
    return route.fulfill({ contentType: "text/html", body: '<html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/bundle.css"><div id="root"></div><script src="/bundle.js"></script></html>' });
  });
  await page.goto(`http://rcn-metadata.test/app/admin?tab=${state.tab || "users"}`);
  await expect(page.locator(".workspace-header")).toBeVisible();
  return state;
}
const writes = (state) => state.calls.filter((call) => call.method === "PUT");
const recovery = (page) => page.getByRole("status", { name: "管理操作回执" });
async function save(page) {
  await page.getByLabel("用户 ID", { exact: true }).fill("alice");
  await page.getByLabel("显示名称", { exact: true }).fill("Alice updated");
  await page.getByRole("button", { name: "保存用户", exact: true }).evaluate((button) => { button.click(); button.click(); });
}

test("ordinary metadata saves issue once under a same-frame double click", async ({ page }) => {
  const state = await fixture(page); await save(page);
  await expect(page.getByText("用户与角色已保存", { exact: true })).toBeVisible();
  expect(writes(state)).toHaveLength(1);
  expect(await page.evaluate(() => Object.keys(sessionStorage).filter((key) => key.startsWith("rcn-metadata-action")))).toEqual([]);
});

test("a lost reply recovers the exact original receipt without another mutation", async ({ page }) => {
  const state = await fixture(page, { dropReply: true }); await save(page);
  await expect(recovery(page)).toContainText("保存用户已完成，已核对原操作");
  expect(writes(state)).toHaveLength(1);
  expect(state.calls.filter((call) => call.path.startsWith("/v1/metadata-operations/")).every((call) => call.method === "GET")).toBe(true);
});

test("reload and leaving the page preserve an offline original operation and do not replay its old write", async ({ page }) => {
  const state = await fixture(page, { dropReply: true, recoveryOffline: true }); await save(page);
  await expect(recovery(page)).toContainText("receipt offline");
  const original = writes(state)[0];
  state.user.active = false; state.user.roles = ["member"]; state.user.display_name = "Later administrator change";
  await page.goto("http://rcn-metadata.test/app/projects");
  await expect(recovery(page)).toContainText("receipt offline");
  await page.reload(); await expect(recovery(page)).toContainText("receipt offline");
  expect(writes(state)).toHaveLength(1);
  state.recoveryOffline = false;
  await recovery(page).getByRole("button", { name: "核对原操作", exact: true }).click();
  await expect(recovery(page)).toContainText("保存用户已完成");
  expect(writes(state)).toEqual([original]); expect(state.user.active).toBe(false);
  expect(state.user.display_name).toBe("Later administrator change");
  expect(state.calls.filter((call) => call.path.startsWith("/v1/metadata-operations/")).every((call) => call.path.endsWith(original.id))).toBe(true);
});

test("an original operation cannot be replaced while its receipt is missing or mismatched", async ({ page }) => {
  const state = await fixture(page, { dropReply: true, recoveryOffline: true }); await save(page);
  await expect(recovery(page)).toContainText("receipt offline");
  await save(page); await expect(page.getByText("上次管理操作的结果尚未确认，请先核对原操作。", { exact: true })).toBeVisible();
  expect(writes(state)).toHaveLength(1);
  state.recoveryOffline = false; state.wrongReceipt = true;
  await recovery(page).getByRole("button", { name: "核对原操作", exact: true }).click();
  await expect(recovery(page)).toContainText("回执与原操作不匹配");
  state.wrongReceipt = false; state.incompleteReceipt = true;
  await recovery(page).getByRole("button", { name: "核对原操作", exact: true }).click();
  await expect(recovery(page)).toContainText("原操作回执不完整");
  expect(await page.evaluate(() => Object.keys(sessionStorage).filter((key) => key.startsWith("rcn-metadata-action")))).toHaveLength(1);
  expect(writes(state)).toHaveLength(1);
});

test("a parseable but incomplete successful response remains pending until the original complete receipt arrives", async ({ page }) => {
  const state = await fixture(page, { incompleteReply: true, recoveryOffline: true }); await save(page);
  await expect(recovery(page)).toContainText("receipt offline");
  expect(writes(state)).toHaveLength(1);
  state.recoveryOffline = false; await recovery(page).getByRole("button", { name: "核对原操作", exact: true }).click();
  await expect(recovery(page)).toContainText("保存用户已完成"); expect(writes(state)).toHaveLength(1);
});

test("permission revocation retains unresolved intent and another actor cannot recover or replace it", async ({ page }) => {
  const state = await fixture(page, { dropReply: true, recoveryOffline: true }); await save(page);
  await expect(recovery(page)).toContainText("receipt offline");
  const first = writes(state)[0]; state.recoveryOffline = false; state.recoveryDenied = true;
  await recovery(page).getByRole("button", { name: "核对原操作", exact: true }).click();
  await expect(recovery(page)).toContainText("permission revoked");
  state.actor = "admin-two"; state.recoveryDenied = false;
  await page.reload(); await expect(page.locator(".nav-account")).toContainText("admin-two");
  await expect(recovery(page)).toHaveCount(0);
  await save(page); await expect(page.getByText("用户与角色已保存", { exact: true })).toBeVisible();
  expect(writes(state)).toHaveLength(2); expect(writes(state)[1].id).not.toBe(first.id);
  const stored = await page.evaluate(() => JSON.parse(sessionStorage.getItem("rcn-metadata-action-v1:admin-one")));
  expect(stored.request_id).toBe(first.id);
});

test("a definite state conflict is shown and the next explicit save uses a new identity", async ({ page }) => {
  const state = await fixture(page, { reject: true }); await save(page);
  await expect(page.getByText("state conflict", { exact: true })).toBeVisible();
  await save(page); await expect(page.getByText("用户与角色已保存", { exact: true })).toBeVisible();
  expect(writes(state)).toHaveLength(2); expect(writes(state)[0].id).not.toBe(writes(state)[1].id);
});

test("PIN recovery keeps only nonsecret operation identity in browser storage", async ({ page }) => {
  const state = await fixture(page, { tab: "breakglass", dropReply: true, recoveryOffline: true });
  await page.getByLabel("新 PIN", { exact: true }).fill("synthetic-PIN-must-never-be-stored");
  await page.getByRole("button", { name: "轮换 PIN", exact: true }).click();
  await expect(recovery(page)).toContainText("receipt offline");
  await expect(page.getByLabel("新 PIN", { exact: true })).toHaveValue("");
  const stored = await page.evaluate(() => JSON.stringify({ ...sessionStorage }));
  expect(stored).not.toContain("synthetic-PIN-must-never-be-stored");
  expect(stored).toContain("break_glass_pin");
  await page.reload(); await expect(recovery(page)).toContainText("receipt offline");
  state.recoveryOffline = false; await recovery(page).getByRole("button", { name: "核对原操作", exact: true }).click();
  await expect(recovery(page)).toContainText("更新管理员 PIN已完成"); expect(writes(state)).toHaveLength(1);
});

test("hidden receipt reads pause and a return event burst performs one original-result read", async ({ page }) => {
  const state = await fixture(page, { dropReply: true, recoveryOffline: true }); await save(page);
  await expect(recovery(page)).toContainText("receipt offline");
  const count = () => state.calls.filter((call) => call.path.startsWith("/v1/metadata-operations/")).length;
  const before = count(); state.recoveryOffline = false;
  await page.evaluate(() => {
    window.__visibility = "hidden";
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => window.__visibility });
    document.dispatchEvent(new Event("visibilitychange")); dispatchEvent(new Event("online")); dispatchEvent(new Event("focus"));
  });
  await page.waitForTimeout(300); expect(count()).toBe(before);
  await page.evaluate(() => {
    window.__visibility = "visible"; document.dispatchEvent(new Event("visibilitychange"));
    dispatchEvent(new Event("online")); dispatchEvent(new Event("focus"));
  });
  await expect(recovery(page)).toContainText("保存用户已完成");
  expect(count()).toBe(before + 1); expect(writes(state)).toHaveLength(1);
});
