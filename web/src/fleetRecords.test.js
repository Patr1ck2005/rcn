import { describe, expect, it } from "vitest";
import { fleetRecords, isHistorical } from "./fleetRecords";

const machines = [
  { machine_id: "old", owner_user_id: "alice", record_state: "revoked_history" },
  { machine_id: "new", owner_user_id: "alice", record_state: "current" },
  { machine_id: "legacy", owner_user_id: "bob" },
];

describe("Fleet record presentation", () => {
  it("keeps ordinary and legacy records current", () => {
    expect(fleetRecords(machines).rows.map((m) => m.machine_id)).toEqual(["new", "legacy"]);
    expect(isHistorical({ machine_id: "offline", record_state: "unknown" })).toBe(false);
  });
  it("searches both sections without changing summary membership", () => {
    const result = fleetRecords(machines, "OLD");
    expect(result.rows).toEqual([]);
    expect(result.historicalMatches.map((m) => m.machine_id)).toEqual(["old"]);
    expect(result.current).toHaveLength(2);
  });
  it("removes historical, unknown, and duplicate IDs from old selected URLs", () => {
    expect(fleetRecords(machines, "", "old,new,new,missing,legacy").selectedIds).toEqual(["new", "legacy"]);
  });
});
