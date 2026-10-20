import { describe, expect, it, vi } from "vitest";
import { metadataCheckpoint, operationCheckpointKey, readOperationCheckpoint, reassignmentCheckpoint, reassignmentReady, recoverMetadataJob, validateReassignment, writeOperationCheckpoint } from "./jobOperations";

const ticket = { ticket_id: "ticket-a", confirmation_hash: "hash-a", job_id: "job-a", issued_by: "actor", action: "cancel_job" };
const original = () => ({ work_unit_id: "unit-a", status: "running", attempts: [{ attempt_id: "attempt-a", external_run_id: "ssh-a", state: "running" }] });
const storage = () => { const data = new Map(); return { getItem: (key) => data.get(key) ?? null, setItem: (key, value) => data.set(key, value), removeItem: (key) => data.delete(key) }; };

describe("durable Job transaction identity", () => {
  it("rejects tickets from another Job or actor before confirmation", () => {
    expect(() => metadataCheckpoint("actor", "job-b", ticket)).toThrow("不匹配");
    expect(() => metadataCheckpoint("other", "job-a", ticket)).toThrow("不匹配");
    expect(metadataCheckpoint("actor", "job-a", ticket).body).toEqual({ ticket_id: "ticket-a", confirmation_hash: "hash-a" });
  });
  it("isolates saved tickets by actor and Job and rejects a corrupt binding", () => {
    const local = storage(), value = metadataCheckpoint("actor", "job-a", ticket);
    writeOperationCheckpoint(local, value);
    expect(readOperationCheckpoint(local, "actor", "job-a", "admin-job")).toEqual(value);
    expect(readOperationCheckpoint(local, "actor", "job-b", "admin-job")).toBeNull();
    expect(readOperationCheckpoint(local, "other", "job-a", "admin-job")).toBeNull();
    local.setItem(operationCheckpointKey("actor", "job-a", "admin-job"), JSON.stringify({ ...value, ticket: { ...ticket, job_id: "job-b" } }));
    expect(() => readOperationCheckpoint(local, "actor", "job-a", "admin-job")).toThrow("不匹配");
  });
  it("rejects a pressure checkpoint whose ticket names another machine", () => {
    const local = storage();
    const value = { actor_id: "actor", subject_id: "machine-a", kind: "pressure", ticket: { machine_id: "machine-b", ticket_id: "pressure", confirmation_hash: "hash" }, body: { ticket_id: "pressure", confirmation_hash: "hash" } };
    writeOperationCheckpoint(local, value);
    expect(() => readOperationCheckpoint(local, "actor", "machine-a", "pressure")).toThrow("检查点不完整");
  });
  it("recovers a receipt before reading its Job without sending a mutation", async () => {
    const value = metadataCheckpoint("actor", "job-a", ticket);
    const request = vi.fn().mockResolvedValueOnce({ request_id: "ticket-a", kind: "admin_job", subject_id: "job-a", result_id: "job-a", state: "completed" }).mockResolvedValueOnce({ job_id: "job-a" });
    await expect(recoverMetadataJob(request, value)).resolves.toEqual({ job_id: "job-a" });
    expect(request.mock.calls).toEqual([["/v1/admin/metadata-operations/ticket-a"], ["/v1/jobs/job-a?view=operational"]]);
    const missing = vi.fn().mockRejectedValue(Object.assign(new Error("not accepted"), { status: 404 }));
    await expect(recoverMetadataJob(missing, value)).rejects.toMatchObject({ status: 404 });
    expect(missing).toHaveBeenCalledTimes(1);
  });
  it("never reads a different Job from a mismatched metadata receipt", async () => {
    const request = vi.fn().mockResolvedValue({ request_id: "ticket-a", kind: "admin_job", subject_id: "job-b", result_id: "job-b", state: "completed" });
    await expect(recoverMetadataJob(request, metadataCheckpoint("actor", "job-a", ticket))).rejects.toThrow("不匹配");
    expect(request).toHaveBeenCalledTimes(1);
  });
  it("freezes the original Attempt and UUID through persistence and subsequent unit changes", () => {
    const unit = original(), value = reassignmentCheckpoint("actor", "job-a", unit, "target", " reason ");
    const local = storage(); writeOperationCheckpoint(local, value);
    unit.attempts.push({ attempt_id: "attempt-new", external_run_id: "ssh-new", state: "running" });
    expect(readOperationCheckpoint(local, "actor", "job-a", "reassign").body).toEqual(value.body);
    expect(value.body).toMatchObject({ expected_attempt_id: "attempt-a", expected_external_run_id: "ssh-a", target_machine_id: "target", reason: "reason" });
    expect(value.body.operation_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(() => reassignmentReady({ job_id: "job-a", work_units: [unit] }, value)).toThrow("原尝试已变更");
  });
  it("requires original terminal cancellation evidence rather than any non-cancel_pending state", () => {
    const unit = original(), value = reassignmentCheckpoint("actor", "job-a", unit, "target", "reason");
    expect(reassignmentReady({ job_id: "job-a", work_units: [unit] }, value)).toBe(false);
    unit.status = "cancelled"; unit.attempts[0].state = "uncertain";
    expect(reassignmentReady({ job_id: "job-a", work_units: [unit] }, value)).toBe(false);
    unit.attempts[0].state = "cancelled";
    expect(reassignmentReady({ job_id: "job-a", work_units: [unit] }, value)).toBe(true);
    unit.attempts[0].external_run_id = "changed";
    expect(() => reassignmentReady({ job_id: "job-a", work_units: [unit] }, value)).toThrow("原尝试已变更");
  });
  it("accepts only bound reassignment envelopes and keeps cancel_requested distinct from completion", () => {
    const value = reassignmentCheckpoint("actor", "job-a", original(), "target", "reason");
    const result = { ...value.body, job: { job_id: "job-a" }, stage: "cancel_requested" };
    expect(validateReassignment(result, value).stage).toBe("cancel_requested");
    expect(() => validateReassignment({ ...result, operation_id: "replacement" }, value)).toThrow("不匹配");
    expect(() => validateReassignment({ ...result, expected_attempt_id: "attempt-new" }, value)).toThrow("不匹配");
    expect(() => validateReassignment({ ...result, stage: "finished" }, value)).toThrow("不匹配");
  });
});
