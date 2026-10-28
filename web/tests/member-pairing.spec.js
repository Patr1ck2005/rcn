// Actual React interactions against intercepted synthetic routes. No center,
// production state, personal credential, listener or installed client is used.
import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

let bundle;
test.beforeAll(async () => {
  const result = await build({ stdin: { contents: `
    import React, {useState} from 'react';
    import {createRoot} from 'react-dom/client';
    import {MemoryRouter} from 'react-router-dom';
    import MemberConnectionSetup from './src/MemberConnectionSetup.jsx';
    import AdminMemberPairing from './src/AdminMemberPairing.jsx';
    import './src/styles.css';
    import './src/memberClient.css';
    function Harness() {
      const [visible,setVisible]=useState(true); const [session,setSession]=useState({connected:false});
      const admin = new URLSearchParams(location.search).has('admin');
      const users=[{user_id:'member-a',display_name:'小林',active:true,roles:['member']},{user_id:'member-b',display_name:'小林',active:true,roles:['member']}];
      return <MemoryRouter><button onClick={()=>setVisible(!visible)}>切换接入页</button>{visible && (admin
        ? <main className="app-page"><AdminMemberPairing actorId="admin" users={users}/></main>
        : <MemberConnectionSetup session={session} onSession={setSession} onRetry={()=>{}} />)}</MemoryRouter>;
    }
    createRoot(document.getElementById('root')).render(<Harness/>);
  `, resolveDir: fileURLToPath(new URL("../", import.meta.url)), loader: "jsx" }, bundle: true, write: false, outdir: "in-memory-only", jsx: "automatic", define: { "process.env.NODE_ENV": '"production"' } });
  bundle = result.outputFiles;
});
const originalId = "11111111-2222-4333-8444-555555555555";
const pending = { schema_version: 1, pairing_id: originalId, state: "pending", phase: "observed", name: "小林", device_name: "小林的笔记本", short_code: "AB12CD", expires_at: "2030-01-01T12:00:00Z", agent: "claude", label: "我的研究助手" };
const connected = { connected: true, online: true, remote_actions_available: true, center_url: "https://compute.example.org", actor: { actor_id: "member-a", roles: ["member"] } };
const agent = { schema_version: 1, target: "claude", agent_id: "aaaaaaaa-2222-4333-8444-555555555555", actor_id: "member-a", center_url: connected.center_url, independent_credential: true, identity_verified: true, credential_included: false, filename: "RCN-Agent-claude.zip", media_type: "application/zip", files: ["rcn-agent-access.json", "AGENT_ACCESS.md", "CLAUDE_SETUP.md"], content_base64: Buffer.from("PK-synthetic-only").toString("base64"), setup_instructions: "Read AGENT_ACCESS.md and preserve the existing project rules." };
const approvedRecord = { ...pending, state: "approved", phase: "connected", doctor_state: "completed", doctor: { ok: true, checks: [], next_actions: [] }, agent_configuration: agent };

async function boot(page, { admin = false, lost = false, initial = null, paused = false, serverPaused = paused, unavailableUntilResend = false } = {}) {
  await page.clock.install();
  if (paused) await page.addInitScript(() => localStorage.setItem("rcn-member-pairing-resume-paused", "true"));
  let record = initial; let activeSession = { connected: false }; let adminLost = lost; let unavailable = false;
  const creates = [], decisions = [], reads = [], pairingActions = [];
  await page.addInitScript(() => Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (value) => { window.__copied = value; } } }));
  await page.route("**/*", async (route) => {
    const request = route.request(); const url = new URL(request.url()); const path = url.pathname;
    if (url.hostname !== "rcn-pairing-ui.test") throw new Error("Unexpected external request");
    if (path === "/") return route.fulfill({ contentType: "text/html", body: '<html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/bundle.css"><div id="root"></div><script src="/bundle.js"></script></html>' });
    if (path === "/bundle.js" || path === "/bundle.css") return route.fulfill({ contentType: path.endsWith("js") ? "application/javascript" : "text/css", body: bundle.find((file) => file.path.endsWith(path.slice(7))).text });
    if (path === "/local/v1/session") return route.fulfill({ json: activeSession });
    if (path === "/local/v1/agent-configurations") return route.fulfill({ json: { agents: [] } });
    if (path === "/local/v1/doctor") return route.fulfill({ json: { ok: true, checks: [{ stage: "identity", status: "passed" }], next_actions: [] } });
    if (path === "/local/v1/member-pairing/group") return route.fulfill({ json: { group_name: "测试课题组", online_member_pairing: true } });
    if (path === "/local/v1/member-pairing" || path.startsWith("/local/v1/member-pairing/")) {
      if (unavailable) return route.fulfill({ status: 503, json: { detail: "synthetic unavailable" } });
      const action = path.match(/^\/local\/v1\/member-pairing\/([^/]+)\/(resume|doctor)$/);
      if (action) {
        expect(request.method()).toBe("POST"); expect(action[1]).toBe(record.pairing_id); expect(request.postDataJSON()).toEqual({});
        pairingActions.push({ pairing_id: action[1], action: action[2] }); serverPaused = false;
        if (record.state === "approved") {
          activeSession = connected;
          record = { ...record, phase: "connected", doctor_state: "completed", doctor: { ok: true, checks: [], next_actions: [] }, agent_configuration: agent };
        }
        return route.fulfill({ json: record });
      }
      if (request.method() === "POST") {
        const body = request.postDataJSON(); creates.push(body);
        record = { ...pending, ...body, state: "pending" };
        if (unavailableUntilResend && creates.length === 1) return route.fulfill({ status: 503, json: { detail: "synthetic interrupted registration" } });
        if (lost && creates.length === 1) return route.abort("connectionreset");
      } else reads.push(path);
      if (unavailableUntilResend && creates.length === 1) return route.fulfill({ status: 503, json: { detail: "synthetic original registration unavailable" } });
      return route.fulfill({ json: record ? serverPaused ? { ...record, phase: "resume_paused", resume_paused: true, agent_configuration: null } : record : { schema_version: 1, state: "not_started", secrets_included: false } });
    }
    if (path === "/v1/admin/member-pairings") { reads.push(path); return route.fulfill({ json: { pairings: record ? [record] : [] } }); }
    if (/\/v1\/admin\/member-pairings\/[^/]+\/(approve|reject)$/.test(path)) {
      decisions.push({ path, body: request.postDataJSON() });
      if (adminLost) { adminLost = false; return route.abort("connectionreset"); }
      record = { ...record, state: path.endsWith("approve") ? "approved" : "rejected", member_id: "member-b" };
      return route.fulfill({ json: record });
    }
    return route.fulfill({ status: 404, json: { detail: "synthetic route unavailable" } });
  });
  await page.goto(`https://rcn-pairing-ui.test/${admin ? "?admin=1" : ""}`);
  return { creates, decisions, reads, pairingActions, record: () => record, revoke: () => { record = { ...record, state: "revoked" }; }, disconnect: () => { unavailable = true; }, approve: (ok = true) => { activeSession = connected; record = { ...record, state: "approved", phase: "connected", doctor_state: "completed", doctor: { ok, checks: [{ stage: "identity", status: ok ? "passed" : "failed", message: ok ? "身份核验通过" : "个人提交权限尚未开通" }], next_actions: [] }, agent_configuration: agent }; } };
}
async function fill(page) {
  await page.getByLabel("课题组中心链接", { exact: true }).fill("https://compute.example.org");
  await page.getByLabel("你的姓名", { exact: true }).fill("小林");
  await page.getByLabel("设备名称", { exact: true }).fill("小林的笔记本");
  await page.getByLabel("入组 Agent 名称", { exact: true }).fill("我的研究助手");
  await page.getByLabel("入组使用的 Agent", { exact: true }).selectOption("claude");
  await expect(page.getByLabel("入组 Agent 名称", { exact: true })).toHaveValue("我的研究助手");
}

test("joins with one UUID, automatically connects and copies instructions only after doctor passes", async ({ page }, testInfo) => {
  const fixture = await boot(page); await fill(page);
  await page.screenshot({ path: testInfo.outputPath("member-pairing-form.png"), fullPage: true });
  await expect(page.getByLabel("个人访问 token", { exact: true })).not.toBeVisible();
  await expect(page.getByLabel("选择私密连接包", { exact: true })).not.toBeVisible();
  await page.getByRole("button", { name: "核对课题组中心", exact: true }).click();
  await expect(page.getByText("课题组：测试课题组", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "申请加入课题组", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(page.getByText("AB12CD", { exact: true })).toBeVisible();
  expect(fixture.creates).toHaveLength(1);
  expect(Object.keys(fixture.creates[0]).sort()).toEqual(["agent", "center_url", "device_name", "label", "name", "pairing_id"]);
  expect(fixture.creates[0].agent).toBe("claude"); expect(fixture.creates[0].label).toBe("我的研究助手");
  expect(await page.evaluate(() => localStorage.getItem("rcn-member-pairing"))).toBe(fixture.creates[0].pairing_id);
  fixture.approve(); await page.clock.runFor(5600);
  await expect(page.getByRole("heading", { name: "已连接，可以提交任务", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "复制指令给 Agent", exact: true }).click();
  expect(await page.evaluate(() => window.__copied)).toBe(agent.setup_instructions);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("member-pairing-ready.png"), fullPage: true });
});

test("lost application reply and browser reload recover the same local record without another create", async ({ page }) => {
  const fixture = await boot(page, { lost: true }); await fill(page);
  await page.getByRole("button", { name: "申请加入课题组", exact: true }).click();
  await expect(page.getByText("AB12CD", { exact: true })).toBeVisible();
  const id = fixture.creates[0].pairing_id; await page.evaluate(() => sessionStorage.clear()); await page.reload();
  await expect(page.getByText(id, { exact: true })).toBeVisible(); expect(fixture.creates).toHaveLength(1);
  expect(fixture.pairingActions).toHaveLength(0);
  await page.clock.runFor(5600);
  const before = fixture.reads.length;
  await page.getByRole("button", { name: "切换接入页", exact: true }).click();
  await expect(page.getByLabel("加入课题组", { exact: true })).toHaveCount(0);
  // A request sent before unmount may reach the intercepted route afterward;
  // it must settle without scheduling another read.
  await page.clock.runFor(6000); const settled = fixture.reads.length;
  await page.clock.runFor(6000); expect(fixture.reads.length).toBe(settled); expect(settled).toBeLessThanOrEqual(before + 1);
});

test("an interrupted initial send retries the exact original request and UUID", async ({ page }) => {
  const fixture = await boot(page, { unavailableUntilResend: true }); await fill(page);
  await page.getByRole("button", { name: "申请加入课题组", exact: true }).click();
  await expect(page.getByRole("heading", { name: "原申请结果待确认", exact: true })).toBeVisible();
  expect(fixture.creates).toHaveLength(1);
  await page.getByRole("button", { name: "按原编号重试发送", exact: true }).click();
  await expect(page.getByText("AB12CD", { exact: true })).toBeVisible();
  expect(fixture.creates).toHaveLength(2); expect(fixture.creates[1]).toEqual(fixture.creates[0]);
});

test("doctor failure preserves the approval but does not show task readiness", async ({ page }) => {
  const fixture = await boot(page, { initial: pending }); fixture.approve(false);
  await page.clock.runFor(5600);
  await expect(page.getByRole("heading", { name: "接入需要恢复", exact: true })).toBeVisible();
  await expect(page.getByText("个人提交权限尚未开通", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "复制指令给 Agent", exact: true })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "已连接，可以提交任务", exact: true })).toHaveCount(0);
  expect(fixture.pairingActions).toHaveLength(0);
  await page.getByRole("button", { name: "重新自检", exact: true }).click();
  await expect(page.getByRole("heading", { name: "自检通过", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "接入需要恢复", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "重新检查原配对", exact: true }).click();
  await expect(page.getByRole("heading", { name: "已连接，可以提交任务", exact: true })).toBeVisible();
  expect(fixture.pairingActions).toEqual([{ pairing_id: originalId, action: "doctor" }]); expect(fixture.creates).toHaveLength(0);
});

test("expired applications require an explicit restart, which keeps the fresh form open", async ({ page }) => {
  const fixture = await boot(page, { initial: { ...pending, state: "expired" } });
  await page.getByRole("button", { name: "重新申请", exact: true }).click();
  await expect(page.getByRole("button", { name: "申请加入课题组", exact: true })).toBeVisible();
  await fill(page); await page.getByRole("button", { name: "申请加入课题组", exact: true }).click();
  await expect(page.getByText("AB12CD", { exact: true })).toBeVisible();
  expect(fixture.creates[0].pairing_id).not.toBe(originalId);
});

test("admin must verify code and explicitly choose among same-name members", async ({ page }, testInfo) => {
  const fixture = await boot(page, { admin: true, initial: pending });
  await expect(page.getByLabel("选择 小林 的身份处理")).toHaveValue("");
  const approve = page.getByRole("button", { name: "批准并接入", exact: true }); await expect(approve).toBeDisabled();
  await page.getByLabel("选择 小林 的身份处理").selectOption("existing");
  await expect(page.getByLabel("为 小林 选择已有成员")).toHaveValue("");
  await page.getByLabel("为 小林 选择已有成员").selectOption("member-b");
  await page.getByLabel("我已通过本人联系渠道核对姓名、设备及配对码。").check();
  await page.getByLabel("核对 小林 的配对码").fill("WRONG"); await expect(approve).toBeDisabled();
  await page.getByLabel("核对 小林 的配对码").fill("AB12CD");
  await page.screenshot({ path: testInfo.outputPath("admin-pairing-review.png"), fullPage: true });
  await approve.evaluate((button) => { button.click(); button.click(); });
  await expect(page.getByText("暂无待审批的入组申请。", { exact: true })).toBeVisible();
  expect(fixture.decisions).toEqual([{ path: `/v1/admin/member-pairings/${originalId}/approve`, body: { create_new: false, member_id: "member-b" } }]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});

test("admin lost approval freezes and restores the original choice, then retries the same application", async ({ page }) => {
  const fixture = await boot(page, { admin: true, lost: true, initial: pending });
  await page.getByLabel("选择 小林 的身份处理").selectOption("new");
  await page.getByLabel("核对 小林 的配对码").fill("AB12CD");
  await page.getByLabel("我已通过本人联系渠道核对姓名、设备及配对码。").check();
  await page.getByRole("button", { name: "批准并接入", exact: true }).click();
  await expect(page.getByText("原审批结果待核对", { exact: true })).toBeVisible();
  await page.reload(); await expect(page.getByText("原操作：新建成员并批准。", { exact: false })).toBeVisible();
  await expect(page.getByLabel("选择 小林 的身份处理")).toHaveCount(0);
  await page.getByRole("button", { name: "重试原审批", exact: true }).click();
  await expect(page.getByText("暂无待审批的入组申请。", { exact: true })).toBeVisible();
  expect(fixture.decisions).toHaveLength(2); expect(fixture.decisions[0]).toEqual(fixture.decisions[1]);
  const before = fixture.reads.length;
  await page.getByRole("button", { name: "切换接入页", exact: true }).click();
  await page.clock.runFor(12000); expect(fixture.reads.length).toBe(before);
});

test("admin rejection ends only the selected application", async ({ page }) => {
  const fixture = await boot(page, { admin: true, initial: pending });
  await page.getByRole("button", { name: "拒绝申请", exact: true }).click();
  await expect(page.getByText("暂无待审批的入组申请。", { exact: true })).toBeVisible();
  expect(fixture.decisions).toEqual([{ path: `/v1/admin/member-pairings/${originalId}/reject`, body: {} }]);
});

test("an explicit sign-out pauses automatic pairing recovery until the member continues", async ({ page }) => {
  const fixture = await boot(page, { initial: approvedRecord, paused: true });
  await expect(page.getByRole("button", { name: "继续配对", exact: true })).toBeVisible();
  await page.reload(); await expect(page.getByRole("button", { name: "继续配对", exact: true })).toBeVisible();
  await page.clock.runFor(12000); expect(fixture.reads).toHaveLength(0); expect(fixture.creates).toHaveLength(0);
  await page.getByRole("button", { name: "继续配对", exact: true }).click();
  await expect(page.getByRole("heading", { name: "已连接，可以提交任务", exact: true })).toBeVisible();
  expect(fixture.creates).toHaveLength(0); expect(fixture.pairingActions).toEqual([{ pairing_id: originalId, action: "resume" }]);
});

test("a server-paused original is recognized without a browser checkpoint and only explicitly resumed", async ({ page }) => {
  const fixture = await boot(page, { initial: pending, serverPaused: true });
  await expect(page.getByRole("button", { name: "继续配对", exact: true })).toBeVisible();
  await page.clock.runFor(12000); expect(fixture.pairingActions).toHaveLength(0); expect(fixture.creates).toHaveLength(0);
  await page.getByRole("button", { name: "继续配对", exact: true }).click();
  await expect(page.getByText("AB12CD", { exact: true })).toBeVisible();
  expect(fixture.pairingActions).toEqual([{ pairing_id: originalId, action: "resume" }]);
});

test("the explicit original recovery action posts resume without changing its UUID", async ({ page }) => {
  const fixture = await boot(page, { initial: pending });
  await page.getByRole("button", { name: "恢复原申请", exact: true }).click();
  await expect.poll(() => fixture.pairingActions.length).toBe(1);
  expect(fixture.pairingActions).toEqual([{ pairing_id: originalId, action: "resume" }]); expect(fixture.creates).toHaveLength(0);
});

for (const cause of ["revoked", "offline"]) {
  test(`a completed pairing stops showing readiness when ${cause}`, async ({ page }) => {
    const fixture = await boot(page, { initial: pending }); fixture.approve();
    await page.clock.runFor(5600);
    await expect(page.getByRole("heading", { name: "已连接，可以提交任务", exact: true })).toBeVisible();
    if (cause === "revoked") fixture.revoke(); else fixture.disconnect();
    await page.clock.runFor(5600);
    await expect(page.getByRole("heading", { name: cause === "revoked" ? "连接已撤销" : "中心连接待恢复", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "复制指令给 Agent", exact: true })).toHaveCount(0);
  });
}
