import { expect, test } from "@playwright/test";
import { memberApiFixture } from "./member-client.fixture";

for (const online of [true, false]) {
  test(`original collection shows preparation or retry and can pause locally (online=${online})`, async ({ page }) => {
    const fixture = await memberApiFixture(page, { online });
    const id = "original-result-collection";
    const operation = {
      operation_id: id, phase: "collecting", job_id: "job-original",
      preview: { project_id: "physics-fixture", profile_id: "comsol-6.4", unit_count: 1 },
      can_confirm: false, can_upload: false, can_collect: false,
      job: { status: "completed", completed_units: 1, total_units: 1 },
      collection_control: { state: online ? "active" : "retry_wait" },
      collection: { stage: "preparing", completed_files: 0, total_files: 1,
        source_checked_bytes: 1048576, source_total_bytes: 4194304 },
    };
    fixture.operations.set(id, operation);
    const pauses = [];
    await page.route(`**/local/v1/operations/${id}/collection/pause`, async (route) => {
      pauses.push(route.request().method());
      const paused = { ...operation, collection_control: { state: "user_paused" } };
      fixture.operations.set(id, paused);
      await route.fulfill({ json: paused });
    });
    await page.goto("/app/runs");
    await expect(page.getByText("源文件校验：1.0 / 4.0 MiB")).toBeVisible();
    if (!online) await expect(page.getByText(/后台将自动续传原任务/)).toBeVisible();
    const pause = page.getByRole("button", { name: "暂停结果下载", exact: true });
    await expect(pause).toBeEnabled();
    await pause.click();
    await expect(page.getByText("结果下载已暂停", { exact: true })).toBeVisible();
    await page.reload();
    await expect(page.getByText("结果下载已暂停", { exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: "job-original", exact: true })).toBeVisible();
    expect(pauses).toEqual(["POST"]);
    expect(fixture.jobsCreated()).toBe(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  });
}
