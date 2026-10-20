import { describe, expect, it } from "vitest";

import { dispatcherActionAvailability } from "./ControlCenter";

describe("dispatcher action availability", () => {
  it("disables start and reconcile while the dispatcher is running", () => {
    const actions = dispatcherActionAvailability({ running: true, control_mode: "open" });

    expect(actions.start.enabled).toBe(false);
    expect(actions.reconcile.enabled).toBe(false);
    expect(actions.drain.enabled).toBe(true);
    expect(actions.stop.enabled).toBe(true);
    expect(actions.restart.enabled).toBe(true);
    expect(actions.force_stop.enabled).toBe(true);
  });

  it("only enables start and reconcile while the dispatcher is stopped", () => {
    const actions = dispatcherActionAvailability({ running: false, control_mode: "drain" });

    expect(actions.start.enabled).toBe(true);
    expect(actions.reconcile.enabled).toBe(true);
    expect(actions.drain.enabled).toBe(false);
    expect(actions.stop.enabled).toBe(false);
    expect(actions.restart.enabled).toBe(false);
    expect(actions.force_stop.enabled).toBe(false);
  });

  it("disables drain when the dispatcher is already draining", () => {
    const actions = dispatcherActionAvailability({ running: true, control_mode: "drain" });

    expect(actions.drain.enabled).toBe(false);
    expect(actions.drain.reason).toContain("已处于排空状态");
  });
});
