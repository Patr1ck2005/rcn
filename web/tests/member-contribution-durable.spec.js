// Source component + local contract fixtures only: no native install or center.
import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

let bundle;
const center = "https://center.example";
const contributionId = "11111111-2222-4333-8444-555555555555";
const invitation = JSON.stringify({ machine_id: "MEMBER-ALICE", owner_user_id: "alice", enrollment_code: "private-invitation-never-store" });
test.beforeAll(async () => {
  bundle = (await build({ stdin: { contents: `
    import React,{useState} from 'react';import{createRoot}from'react-dom/client';
    import{MemberContribution}from'./src/MemberClient.jsx';
    function Harness(){const[session,setSession]=useState({actor:{actor_id:'alice'},center_url:'${center}',online:!location.search.includes('offline')});
      window.setContributionScope=(changes)=>setSession(value=>({...value,...changes}));
      return <MemberContribution key={session.actor.actor_id+':'+session.center_url} session={session} online={session.online!==false}/>;}
    createRoot(document.getElementById('root')).render(<Harness/>);`,
    resolveDir: fileURLToPath(new URL("../", import.meta.url)), loader: "jsx" },
    bundle: true, write: false, outdir: "ignored-in-memory", jsx: "automatic",
    define: { "process.env.NODE_ENV": '"production"' } })).outputFiles;
});

async function boot(page, options = {}) {
  const state = { calls: [], posts: [], operations: new Map(), effects: 0,
    receiptOffline: Boolean(options.receiptOffline), conflict: Boolean(options.conflict), scopeChanged: false,
    contribution: { contribution_id: contributionId, revision: 0, configured: Boolean(options.configured),
      machine_id: options.configured ? "MEMBER-ALICE" : undefined,
      work_root: "C:\\SyntheticMemberOnly\\worker", preferences: { max_cpus: 4, max_memory_mb: 4096, memory_reserve_mb: 1024, paused: false },
      pending_operations: [] } };
  await page.route("**/*", async (route) => {
    const request = route.request(), url = new URL(request.url());
    if (url.hostname !== "rcn-contribution.test") throw new Error("Unexpected external fixture request");
    if (url.pathname === "/bundle.js") return route.fulfill({ contentType: "application/javascript", body: bundle.find((f) => f.path.endsWith(".js")).text });
    if (url.pathname === "/bundle.css") return route.fulfill({ contentType: "text/css", body: bundle.find((f) => f.path.endsWith(".css")).text });
    if (!url.pathname.startsWith("/local/")) return route.fulfill({ contentType: "text/html", body: '<html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/bundle.css"><div id="root"></div><script src="/bundle.js"></script></html>' });
    const body = request.postDataJSON();
    state.calls.push({ path: url.pathname, method: request.method(), body });
    const json = (value, status = 200) => route.fulfill({ json: value, status });
    if (state.scopeChanged) return json({ detail: "original identity or center changed" }, 403);
    if (url.pathname === "/local/v1/contribution") return json(state.contribution);
    if (url.pathname.includes("/contribution/operations/")) {
      if (state.receiptOffline) return json({ detail: "receipt read offline" }, 503);
      const result = state.operations.get(url.pathname.split("/").at(-1));
      return json(result || { detail: { message: "original absent", reason_code: "contribution_operation_not_found" } }, result ? 200 : 404);
    }
    const kind = url.pathname.endsWith("/setup") ? "setup" : "preferences";
    state.posts.push({ kind, body });
    if (state.operations.has(body.operation_id)) return json(state.operations.get(body.operation_id));
    if (state.conflict) { state.contribution.revision += 1; return json({ detail: "state revision changed" }, 409); }
    expect(body.operation_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(body.expected_revision).toBe(state.contribution.revision);
    if (!options.policyConflict) state.effects += 1;
    const { operation_id, expected_revision, invite, accepted, work_root, ...preferences } = body;
    if (!options.unknown && !options.policyConflict || options.localPause) state.contribution = { ...state.contribution, configured: true, machine_id: "MEMBER-ALICE", revision: state.contribution.revision + 1, policy_sync_pending: Boolean(options.offline || options.localPause),
      preferences: { ...state.contribution.preferences, ...preferences } };
    const operation = { operation_id, expected_revision, kind, actor_id: "alice", center_url: center,
      machine_id: "MEMBER-ALICE", payload_sha256: "a".repeat(64), status: options.policyConflict ? "failed" : options.unknown ? "unknown" : "completed" };
    if (options.policyConflict) operation.error = { reason_code: "machine_policy_revision_conflict", message: "中心策略已变更，原请求未应用" };
    const result = { operation, result: options.unknown && !options.localPause ? null : state.contribution };
    state.operations.set(operation_id, result);
    if (options.unknown) state.contribution.pending_operations = [operation];
    if (options.lostReply || options.unknown) return route.abort("connectionreset");
    return json(result);
  });
  await page.goto(`https://rcn-contribution.test/${options.offline ? "?offline" : ""}`);
  await expect(page.getByLabel(options.configured ? "最多调度 CPU 线程" : "计算工作目录")).toHaveValue(options.configured ? "4" : state.contribution.work_root);
  return state;
}

async function submit(page) {
  await page.getByLabel("私密 v2 机器邀请").fill(invitation);
  await page.getByLabel("我同意在所设资源范围内贡献计算").check();
  await page.getByRole("button", { name: "同意并接入计算", exact: true }).evaluate((button) => { button.click(); button.click(); });
}

test("setup double click creates one original operation and never stores its invitation", async ({ page }) => {
  const state = await boot(page);
  await submit(page);
  await expect(page.getByRole("heading", { name: "MEMBER-ALICE", exact: true })).toBeVisible();
  expect(state.posts).toHaveLength(1); expect(state.effects).toBe(1);
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage }))).not.toContain("private-invitation");
});

for (const configured of [false, true]) test(`${configured ? "preferences" : "setup"} accepted lost reply reload recovers by original GET only`, async ({ page }) => {
  const state = await boot(page, { configured, lostReply: true, receiptOffline: true });
  if (configured) {
    await page.getByLabel("内存预算（MiB）").fill("2048");
    await page.getByRole("button", { name: "保存资源预算与时间", exact: true }).evaluate((button) => { button.click(); button.click(); });
  } else await submit(page);
  await expect(page.getByRole("alert")).toContainText("原请求编号已保留");
  const id = state.posts[0].body.operation_id;
  const persisted = await page.evaluate(() => JSON.stringify({ ...localStorage }));
  expect(persisted).toContain(id); expect(persisted).not.toMatch(/private-invitation|invite|max_memory_mb|weekly_windows/);
  await page.reload();
  await expect(page.getByRole("alert")).toContainText("receipt read offline");
  await expect(page.locator(`[data-contribution-operation="${id}"]`)).toBeVisible();
  state.receiptOffline = false;
  await page.getByRole("button", { name: "核对原接入请求", exact: true }).click();
  await expect(page.locator("[data-contribution-operation]")).toHaveCount(0);
  expect(state.posts).toHaveLength(1); expect(state.effects).toBe(1);
  expect(state.calls.filter((call) => call.path.includes("/operations/")).every((call) => call.path.endsWith(id) && call.method === "GET")).toBe(true);
});

test("unknown setup survives reload without restarting and clears the delivered secret", async ({ page }) => {
  const state = await boot(page, { unknown: true });
  await submit(page);
  await expect(page.getByText("原请求结果尚未确认", { exact: false })).toBeVisible();
  await expect(page.getByLabel("私密 v2 机器邀请")).toHaveValue("");
  await page.reload();
  await expect(page.locator("[data-contribution-operation]")).toHaveCount(1);
  await expect(page.getByRole("button", { name: "结束已核实未送达的请求", exact: true })).toHaveCount(0);
  await page.getByLabel("私密 v2 机器邀请").fill(invitation);
  await page.getByLabel("我同意在所设资源范围内贡献计算").check();
  await expect(page.getByRole("button", { name: "同意并接入计算", exact: true })).toBeDisabled();
  expect(state.posts).toHaveLength(1); expect(state.effects).toBe(1);
});

for (const change of ["actor", "center"]) test(`${change} change hides old recovery and cannot read or submit through its scope`, async ({ page }) => {
  const state = await boot(page, { lostReply: true, receiptOffline: true });
  await submit(page);
  await expect(page.getByRole("alert")).toContainText("原请求编号已保留");
  const reads = state.calls.filter((call) => call.path.includes("/operations/")).length;
  state.scopeChanged = true;
  await page.evaluate((kind) => window.setContributionScope(kind === "actor" ? { actor: { actor_id: "bob" } } : { center_url: "https://another.example" }), change);
  await expect(page.getByRole("alert")).toContainText("original identity or center changed");
  await expect(page.locator("[data-contribution-operation]")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "同意并接入计算", exact: true })).toBeDisabled();
  expect(state.calls.filter((call) => call.path.includes("/operations/")).length).toBe(reads);
  expect(state.posts).toHaveLength(1);
});

test("a state conflict requires original 404 and explicit closure before a new intent", async ({ page }) => {
  const state = await boot(page, { conflict: true });
  await submit(page);
  await expect(page.getByRole("button", { name: "结束已核实未送达的请求", exact: true })).toBeVisible();
  expect(state.posts).toHaveLength(1); expect(state.effects).toBe(0);
  const oldId = state.posts[0].body.operation_id;
  await page.getByRole("button", { name: "结束已核实未送达的请求", exact: true }).click();
  state.conflict = false;
  await page.reload();
  await submit(page);
  await expect(page.getByRole("heading", { name: "MEMBER-ALICE", exact: true })).toBeVisible();
  expect(state.posts).toHaveLength(2); expect(state.effects).toBe(1);
  expect(state.posts[1].body.operation_id).not.toBe(oldId);
});

test("offline pause has a durable original ID while resume remains disabled", async ({ page }) => {
  const state = await boot(page, { configured: true, offline: true });
  await page.getByRole("button", { name: "暂停接活", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(page.getByRole("button", { name: "恢复接活", exact: true })).toBeDisabled();
  await expect(page.getByText("本机暂停已生效，中心策略尚未同步。", { exact: false })).toBeVisible();
  expect(state.posts).toHaveLength(1);
  const { operation_id, expected_revision, ...business } = state.posts[0].body;
  expect(business).toEqual({ paused: true }); expect(expected_revision).toBe(0);
  expect(operation_id).toMatch(/^[0-9a-f-]{36}$/);
});

test("a terminal center CAS conflict shows the original failure without retrying", async ({ page }) => {
  const state = await boot(page, { configured: true, policyConflict: true });
  await page.getByRole("button", { name: "保存资源预算与时间", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("中心策略已变更");
  await expect(page.locator("[data-contribution-operation]")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "保存资源预算与时间", exact: true })).toBeEnabled();
  expect(state.posts).toHaveLength(1); expect(state.effects).toBe(0);
});

test("an unknown center child preserves the proven local pause and original checkpoint", async ({ page }) => {
  const state = await boot(page, { configured: true, unknown: true, localPause: true });
  await page.getByRole("button", { name: "暂停接活", exact: true }).click();
  await expect(page.getByRole("button", { name: "恢复接活", exact: true })).toBeDisabled();
  await expect(page.getByText("本机暂停已生效，中心策略尚未同步。", { exact: false })).toBeVisible();
  await expect(page.locator("[data-contribution-operation]")).toHaveCount(1);
  await page.reload();
  await expect(page.getByRole("button", { name: "恢复接活", exact: true })).toBeDisabled();
  await expect(page.locator("[data-contribution-operation]")).toHaveCount(1);
  expect(state.posts).toHaveLength(1); expect(state.effects).toBe(1);
});
