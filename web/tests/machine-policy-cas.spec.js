import { build } from "esbuild";
import { expect, test } from "@playwright/test";

let bundle;
test.beforeAll(async () => {
  bundle = (await build({ stdin: { contents: `
    import React from "react";
    import {createRoot} from "react-dom/client";
    import {MachinePolicyEditor} from "./src/MachineSettings.jsx";
    import {api} from "./src/api.js";
    function Harness(){
      const [value,setValue]=React.useState(null);
      const refresh=async()=>setValue(await api("/v1/machines/M/detail"));
      window.refreshPolicy=refresh;
      React.useEffect(()=>{api("/v1/me").then(refresh)},[]);
      return value ? <MachinePolicyEditor {...value} canEdit onSaved={refresh}/> : <p>Loading</p>;
    }
    createRoot(document.getElementById("root")).render(<Harness/>);
  `, resolveDir: process.cwd(), loader: "jsx" }, bundle: true, write: false, jsx: "automatic",
    define: { "process.env.NODE_ENV": '"production"' } })).outputFiles[0].text;
});

async function boot(page, { missingRevision = false } = {}) {
  const state = { revision: "a".repeat(64), calls: [], policy: {
    machine_id: "M", owner_mode: "open", max_cpus: 8, max_memory_mb: 4096, max_gpus: 0,
    max_concurrent_units: 2, keyboard_idle_min_s: 0, non_pool_cpu_max_percent: 80,
    cpu_window_s: 5, memory_reserve_mb: 0, shared_machine: false, weekly_windows: {}, timezone: "UTC",
    updated_at: "2026-10-17T12:00:00Z",
  } };
  await page.route("**/*", async (route) => {
    const request = route.request(), url = new URL(request.url());
    const json = (value, status = 200) => route.fulfill({ status, json: value });
    if (url.pathname === "/bundle.js") return route.fulfill({ contentType: "application/javascript", body: bundle });
    if (url.pathname === "/v1/me") return json({ actor_id: "owner", roles: ["machine_owner"] });
    if (url.pathname === "/v1/machines/M/detail") return json({ machine: { machine_id: "M", total_cpus: 8, total_memory_mb: 4096, total_gpus: 0 }, policy: state.policy,
      policyRevisionHash: missingRevision ? undefined : state.revision, config: { max_concurrent_units: 2 } });
    if (url.pathname === "/v1/machines/M/policy" && request.method() === "PUT") {
      const body = request.postDataJSON(); state.calls.push({ body, id: request.headers()["x-rcn-request-id"] });
      if (body.expected_policy_payload_sha256 !== state.revision) return json({ detail: {
        reason_code: "machine_policy_revision_conflict", message: "机器策略已变化，请读取最新策略后重新编辑。",
      } }, 409);
      const { expected_policy_payload_sha256, ...policy } = body;
      state.policy = { ...policy, updated_at: "2026-10-17T12:01:00Z" }; state.revision = "c".repeat(64);
      return json(state.policy);
    }
    if (url.pathname.startsWith("/v1/")) return json({ detail: "unexpected test request" }, 500);
    return route.fulfill({ contentType: "text/html", body: '<html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><div id="root"></div><script src="/bundle.js"></script></html>' });
  });
  await page.goto("http://rcn-policy.test/");
  await expect(page.getByLabel("所有者模式", { exact: true })).toHaveValue("open");
  return state;
}

test("a dirty policy keeps its original revision and cannot reopen a newer pause", async ({ page }) => {
  const state = await boot(page);
  await page.getByRole("spinbutton").nth(4).fill("4");
  state.policy = { ...state.policy, owner_mode: "paused" }; state.revision = "b".repeat(64);
  await page.evaluate(() => window.refreshPolicy());
  await expect(page.getByRole("status")).toContainText("当前草稿仍绑定原版本");
  await expect(page.getByLabel("所有者模式", { exact: true })).toHaveValue("open");
  await page.getByRole("button", { name: "保存机器策略", exact: true }).click();
  await expect(page.getByText("机器策略已变化，请读取最新策略后重新编辑。", { exact: true })).toBeVisible();
  expect(state.calls).toHaveLength(1); expect(state.calls[0].body.expected_policy_payload_sha256).toBe("a".repeat(64));
  expect(state.policy.owner_mode).toBe("paused");
  await page.getByRole("button", { name: "使用最新策略重新编辑", exact: true }).click();
  await expect(page.getByLabel("所有者模式", { exact: true })).toHaveValue("paused");
  await page.getByRole("button", { name: "保存机器策略", exact: true }).evaluate((button) => { button.click(); button.click(); });
  await expect(page.getByText("机器策略已保存", { exact: true })).toBeVisible();
  expect(state.calls).toHaveLength(2); expect(state.calls[1].body.expected_policy_payload_sha256).toBe("b".repeat(64));
  expect(state.calls[0].id).not.toBe(state.calls[1].id); expect(state.policy.owner_mode).toBe("paused");
});

test("a clean editor adopts the matching refreshed policy and version", async ({ page }) => {
  const state = await boot(page);
  state.policy = { ...state.policy, owner_mode: "paused" }; state.revision = "b".repeat(64);
  await page.evaluate(() => window.refreshPolicy());
  await expect(page.getByLabel("所有者模式", { exact: true })).toHaveValue("paused");
  await page.getByRole("button", { name: "保存机器策略", exact: true }).click();
  await expect(page.getByText("机器策略已保存", { exact: true })).toBeVisible();
  expect(state.calls[0].body.expected_policy_payload_sha256).toBe("b".repeat(64));
  expect(state.policy.owner_mode).toBe("paused");
});

test("missing revision refuses the write before creating an operation", async ({ page }) => {
  const state = await boot(page, { missingRevision: true });
  await page.getByRole("button", { name: "保存机器策略", exact: true }).click();
  await expect(page.getByText("未取得机器策略版本，请重新读取后保存。", { exact: true })).toBeVisible();
  expect(state.calls).toEqual([]);
  expect(await page.evaluate(() => Object.keys(sessionStorage))).toEqual([]);
});
