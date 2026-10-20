import { describe, expect, it, vi } from "vitest";
import { alertTransitionCheckpoint, loadAlertTransitions, recoverAlertTransition, saveAlertTransition } from "./alertTransitionCheckpoint";
const alert = { alert_id: "alert", status: "snoozed", last_seen_at: "2026-10-17T12:00:00Z", occurrence_count: 2, acknowledged_at: null, snoozed_until: "2026-10-17T13:00:00Z", resolved_at: null };
describe("alert transition immutable intent", () => {
  it("freezes the absolute deadline and all six CAS fields across reloads", () => {
    const values = new Map(), storage = { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) };
    const value = alertTransitionCheckpoint("actor", alert, "snoozed", 1, Date.parse("2026-10-17T12:30:00Z"));
    saveAlertTransition(storage, value);
    expect(loadAlertTransitions(storage, "actor").alert.body).toEqual(value.body);
    expect(value.body).toMatchObject({ expected_status: "snoozed", expected_last_seen_at: alert.last_seen_at, expected_occurrence_count: 2, expected_acknowledged_at: null, expected_snoozed_until: alert.snoozed_until, expected_resolved_at: null, snoozed_until: "2026-10-17T13:30:00.000Z" });
    expect(loadAlertTransitions(storage, "other")).toEqual({});
  });
  it("queries only the original actor-scoped receipt and rejects wrong targets", async () => {
    const value = alertTransitionCheckpoint("actor", alert, "resolved");
    const request = vi.fn().mockResolvedValue({ request_id: value.body.request_id, kind: "alert_transition", subject_id: "other", result_id: "other", state: "completed" });
    await expect(recoverAlertTransition(request, value)).rejects.toThrow("不匹配");
    expect(request.mock.calls).toEqual([[`/v1/admin/metadata-operations/${value.body.request_id}`]]);
  });
});
