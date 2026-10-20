import { describe, expect, it } from "vitest";

import { initialRequestState, settleResourceRequests } from "./AsyncState";

describe("async content state", () => {
  it("distinguishes initial loading from loaded empty content", () => {
    expect(initialRequestState(["users"]).users).toEqual({ status: "loading", error: "" });
  });

  it("publishes a fast resource without waiting for an unrelated slow resource", async () => {
    let releaseSlow;
    const slow = new Promise((resolve) => { releaseSlow = resolve; });
    const published = [];
    const operation = settleResourceRequests(
      ["users", "settings"],
      (key) => key === "users" ? Promise.resolve([{ user_id: "ready" }]) : slow,
      (key, value) => published.push([key, value]),
      () => {},
    );

    await Promise.resolve();
    await Promise.resolve();
    expect(published).toEqual([["users", [{ user_id: "ready" }]]]);

    releaseSlow({ pressure_policy: {} });
    await operation;
    expect(published.map(([key]) => key)).toEqual(["users", "settings"]);
  });

  it("reports one failed resource without discarding successful siblings", async () => {
    const published = [];
    const failed = [];
    const results = await settleResourceRequests(
      ["users", "settings"],
      (key) => key === "users" ? Promise.resolve([]) : Promise.reject(new Error("settings unavailable")),
      (key) => published.push(key),
      (key, error) => failed.push([key, error.message]),
    );

    expect(results.map((result) => result.status)).toEqual(["fulfilled", "rejected"]);
    expect(published).toEqual(["users"]);
    expect(failed).toEqual([["settings", "settings unavailable"]]);
  });
});
