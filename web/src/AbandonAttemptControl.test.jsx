import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import AbandonAttemptControl, { abandonRequest, abandonmentScope, unitCanAbandon } from "./AbandonAttemptControl";

const lostUnit = () => ({ work_unit_id: "unit-old", status: "reconcile_pending", attempt_count: 1, max_attempts: 3,
  assigned_machine_id: "demo-node-a", attempts: [{ attempt_id: "attempt-old", state: "uncertain", machine_id: "demo-node-a", external_run_id: "ssh-old" }] });

describe("explicit administrator abandonment", () => {
  it("offers manual recovery only to administrators for unresolved original attempts", () => {
    expect(renderToStaticMarkup(<AbandonAttemptControl admin jobId="job-original" unit={lostUnit()} />)).toContain("放弃旧尝试并重算");
    expect(renderToStaticMarkup(<AbandonAttemptControl jobId="job-original" unit={lostUnit()} />)).toBe("");
    expect(unitCanAbandon({ ...lostUnit(), status: "running", attempts: [{ attempt_id: "attempt-old", state: "running" }] })).toBe(false);
    expect(unitCanAbandon({ ...lostUnit(), status: "completed" })).toBe(false);
    expect(unitCanAbandon({ ...lostUnit(), attempt_count: 3 })).toBe(false);
  });
  it("binds retries to the exact old identity without mutating the unit", () => {
    const unit = lostUnit();
    const request = abandonRequest("job-original", unit, "  manual recovery  ");
    unit.attempts[0].attempt_id = "attempt-new";
    unit.attempts[0].external_run_id = "ssh-new";
    expect(request).toEqual({ job_id: "job-original", work_unit_id: "unit-old", machine_id: "demo-node-a", body: {
      expected_attempt_id: "attempt-old", expected_external_run_id: "ssh-old", reason: "manual recovery", operation_id: "admin-abandon-attempt-old",
    } });
  });
  it("includes an explicit null external identity and a stable operation ID", () => {
    const unit = lostUnit(); delete unit.attempts[0].external_run_id;
    expect(abandonRequest("job-original", unit, "recover").body.expected_external_run_id).toBe(null);
    expect(abandonRequest("job-original", unit, "recover")).toEqual(abandonRequest("job-original", unit, "recover"));
    expect(() => abandonRequest("job-original", unit, " ")).toThrow("请填写");
    expect(() => abandonRequest("job-original", { ...unit, status: "completed" }, "recover")).toThrow("当前单元");
  });
  it("isolates a successor and a different actor from an old completion scope", () => {
    const first = lostUnit();
    const old = abandonmentScope("admin-one", "job-original", first);
    expect(abandonmentScope("admin-two", "job-original", first)).not.toBe(old);
    expect(abandonmentScope("admin-one", "another-job", first)).not.toBe(old);
    first.attempts.push({ attempt_id: "attempt-new", external_run_id: "ssh-new", state: "uncertain" }); first.attempt_count = 2;
    expect(abandonmentScope("admin-one", "job-original", first)).not.toBe(old);
    expect(unitCanAbandon(first)).toBe(true);
  });
});
