import { describe, expect, it, vi } from "vitest";
import { confirmControlTicket } from "./controlConfirmation";

const body = { ticket_id: "ticket-original", confirmation_hash: "original-hash" };
const run = { operation_id: "operation-original", ticket_id: body.ticket_id, state: "accepted" };
describe("audited control reply recovery", () => {
  it("recovers an accepted operation after its confirm response is lost", async () => {
    const request = vi.fn().mockRejectedValueOnce(new TypeError("network lost")).mockResolvedValueOnce(run);
    expect(await confirmControlTicket(request, "/confirm", body)).toEqual(run);
    expect(request.mock.calls).toEqual([
      ["/confirm", { method: "POST", body: JSON.stringify(body) }],
      ["/v1/admin/control-runs/by-ticket/ticket-original"],
    ]);
  });
  it("queries an uncertain original ticket before retrying and avoids another write when found", async () => {
    const request = vi.fn().mockResolvedValue(run);
    expect(await confirmControlTicket(request, "/confirm", body, { recoverFirst: true })).toBe(run);
    expect(request).toHaveBeenCalledTimes(1);
    expect(request.mock.calls[0][0]).toContain("by-ticket");
  });
  it("repeats only the original confirmation when no accepted run exists", async () => {
    const request = vi.fn().mockRejectedValueOnce(Object.assign(new Error("not found"), { status: 404 })).mockResolvedValueOnce(run);
    expect(await confirmControlTicket(request, "/confirm", body, { recoverFirst: true })).toEqual(run);
    expect(request.mock.calls[1]).toEqual(["/confirm", { method: "POST", body: JSON.stringify(body) }]);
  });
  it("keeps an ambiguous confirmation unresolved if the recovery read also fails", async () => {
    const failure = new Error("lost reply");
    const request = vi.fn().mockRejectedValueOnce(failure).mockRejectedValueOnce(new Error("offline"));
    await expect(confirmControlTicket(request, "/confirm", body)).rejects.toBe(failure);
  });
  it("rejects an unrelated ticket receipt", async () => {
    const request = vi.fn().mockResolvedValue({ ...run, ticket_id: "other-ticket" });
    await expect(confirmControlTicket(request, "/confirm", body)).rejects.toThrow("原票据");
  });
});
