import { describe, expect, it, vi } from "vitest";
import { loadSolverApproval, recoverSolverApproval, saveSolverApproval, solverApprovalCheckpoint } from "./solverApprovalCheckpoint";
describe("solver approval issuance identity", () => {
  it("freezes the payload and restores the same UUID without manufacturing an approval ID", () => {
    const values = new Map(), storage = { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) };
    const payload = { approved_by: "actor", project_id: "project", execution_profile_id: "profile", mesh_policy: { size: "fine" } };
    const value = solverApprovalCheckpoint("actor", payload, { project_id: "project" });
    saveSolverApproval(storage, value); payload.mesh_policy.size = "changed";
    expect(loadSolverApproval(storage, "actor")).toEqual(value);
    expect(value.payload.mesh_policy.size).toBe("fine"); expect(value.payload).not.toHaveProperty("approval_id");
    expect(loadSolverApproval(storage, "other")).toBeNull();
  });
  it("recovers the original receipt then list and preserves revoked approvals", async () => {
    const value = solverApprovalCheckpoint("actor", { approved_by: "actor", project_id: "project", execution_profile_id: "profile" }, {});
    const approval = { approval_id: "original", project_id: "project", execution_profile_id: "profile", active: false };
    const request = vi.fn().mockResolvedValueOnce({ request_id: value.request_id, kind: "solver_approval", result_id: "original", state: "completed" }).mockResolvedValueOnce([approval]);
    expect((await recoverSolverApproval(request, value)).approval.active).toBe(false);
    expect(request.mock.calls).toEqual([[`/v1/admin/metadata-operations/${value.request_id}`], ["/v1/solver-approvals"]]);
    const missing = vi.fn().mockRejectedValue(Object.assign(new Error("not accepted"), { status: 404 }));
    await expect(recoverSolverApproval(missing, value)).rejects.toMatchObject({ status: 404 });
    expect(missing).toHaveBeenCalledTimes(1);
  });
});
