import { expect, test } from "@playwright/test";

test.skip(!process.env.RCN_MEMBER_TASK_PACKAGE, "Started by the explicit real local broker integration fixture");

test("real local broker imports and recovers one original Job with hash-verified files", async ({ page }) => {
  test.setTimeout(90000);
  const failures = [];
  page.on("pageerror", (error) => failures.push(error.message));
  await page.goto("/connect");
  await page.getByLabel("中心 HTTPS 地址").fill("https://center.example");
  await page.getByLabel("个人访问 token").fill("personal-a");
  await page.getByRole("button", { name: "连接并进入" }).click();
  await expect(page.getByRole("heading", { name: "提交科研任务" })).toBeVisible();
  await page.getByLabel("选择任务包", { exact: true }).setInputFiles(process.env.RCN_MEMBER_TASK_PACKAGE);
  await expect(page.getByRole("heading", { name: "任务包预览" })).toBeVisible();
  await page.getByRole("button", { name: "生成提交预览", exact: true }).click();
  await page.getByRole("button", { name: "确认提交", exact: true }).click();
  await expect(page.getByText("响应中断，已恢复原提交记录。")).toBeVisible();
  const operationId = await page.locator(".member-operation").getAttribute("data-operation-id");
  const jobId = await page.locator(".member-job-link").innerText();
  await page.getByRole("button", { name: "上传 / 继续上传" }).click();
  await expect(page.getByText("上传中断", { exact: true })).toBeVisible({ timeout: 15000 });
  await page.getByRole("button", { name: "上传 / 继续上传" }).click();
  await expect(page.getByText("计算进度：1 / 1 单元")).toBeVisible({ timeout: 15000 });
  await page.getByRole("button", { name: "下载并核验结果" }).click();
  await expect(page.getByText("下载中断", { exact: true })).toBeVisible({ timeout: 15000 });
  await page.getByRole("button", { name: "下载并核验结果" }).click();
  await expect(page.getByText("结果已下载并通过校验")).toBeVisible({ timeout: 15000 });
  await page.getByRole("button", { name: "核对原提交" }).click();
  await expect(page.locator(".member-operation")).toHaveAttribute("data-operation-id", operationId);
  await expect(page.locator(".member-job-link")).toHaveText(jobId);
  await page.goto("/app/runs"); await page.reload();
  await expect(page.getByText("结果已下载并通过校验")).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem("rcn-token"))).toBeNull();
  expect(await page.evaluate(() => localStorage.getItem("rcn-token"))).toBeNull();
  expect(failures).toEqual([]);
});
