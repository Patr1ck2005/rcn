import { describe, expect, it, vi } from "vitest";
import { mutateAndRecover, operationActions, operationLabel, requiresUnitCount, validateUnitCount } from "./memberClientModel";

describe("durable member submission", () => {
  it("recovers the same operation after an accepted confirmation response is lost", async () => {
    const recovered = { operation_id: "original", job_id: "job-one", phase: "confirmed" };
    const request = vi.fn().mockRejectedValueOnce(new Error("response lost")).mockResolvedValueOnce(recovered);
    await expect(mutateAndRecover(request, "original", "confirm")).resolves.toMatchObject(recovered);
    expect(request.mock.calls.map(([path]) => path)).toEqual(["/local/v1/operations/original/confirm", "/local/v1/operations/original"]);
    expect(request).toHaveBeenCalledTimes(2);
  });
  it("reports revoked rights without retrying the write", async () => {
    const error = Object.assign(new Error("project grant revoked"), { status: 403 });
    const request = vi.fn().mockRejectedValue(error);
    await expect(mutateAndRecover(request, "original", "confirm")).rejects.toBe(error);
    expect(request).toHaveBeenCalledTimes(1);
  });
  it("keeps the original identifier when both the mutation and readback fail", async () => {
    const request = vi.fn().mockRejectedValue(new Error("offline"));
    await expect(mutateAndRecover(request, "original", "upload")).rejects.toThrow("原提交编号已保留");
    expect(request.mock.calls[1][0]).toBe("/local/v1/operations/original");
  });
  it("requires explicit partition information when both duration and count are unknown", () => {
    expect(requiresUnitCount({})).toBe(true);
    expect(requiresUnitCount({ unit_count: 4 })).toBe(false);
    expect(requiresUnitCount({ estimated_duration_seconds: 60 })).toBe(false);
    expect(requiresUnitCount({ unit_count: 4, missing_fields: ["requested_unit_count"] })).toBe(true);
    expect(validateUnitCount("4")).toBe(4);
    for (const value of ["", 0, -1, 1.5, "unknown"]) expect(() => validateUnitCount(value)).toThrow();
  });
  it("separates uploaded computation from verified result download", () => {
    const ready = { phase: "uploaded", job_id: "job-one", job: { status: "completed" }, upload: { state: "completed" } };
    expect(operationLabel(ready)).toBe("计算完成");
    expect(operationActions(ready)).toMatchObject({ hasJob: true, canConfirm: false, canUpload: false, canCollect: true, verified: false });
    expect(operationActions({ ...ready, collection: { state: "verified" } })).toMatchObject({ canCollect: false, verified: true });
    expect(operationLabel({ ...ready, collection: { state: "verified" } })).toBe("结果已核验");
  });
  it("distinguishes automatic original-download recovery from an explicit pause", () => {
    const operation = { phase: "collection-interrupted", job_id: "job-one", job: { status: "completed" }, collection_control: { state: "retry_wait" } };
    expect(operationLabel(operation)).toBe("等待自动续传");
    expect(operationActions(operation).canPauseCollection).toBe(true);
    const paused = { ...operation, collection_control: { state: "user_paused" } };
    expect(operationLabel(paused)).toBe("结果下载已暂停");
    expect(operationActions(paused)).toMatchObject({ canCollect: true, canPauseCollection: false, verified: false });
    expect(operationLabel({ ...operation, collection_control: { state: "fault_paused" } })).toBe("下载需要处理");
  });
});
