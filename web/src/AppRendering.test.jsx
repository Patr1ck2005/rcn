import { describe, expect, it } from "vitest";
import { formatTime } from "./App";

describe("shared console timestamp formatting", () => {
  it.each([null, undefined, ""])("keeps an absent timestamp (%s) explicit", (value) => {
    expect(formatTime(value)).toBe("-");
  });

  it.each(["not-a-timestamp", "2026-99-99T00:00:00Z"])("does not crash a retained record with invalid timestamp %s", (value) => {
    expect(formatTime(value)).toBe("-");
  });

  it("preserves the console's date, time and seconds for a valid timestamp", () => {
    const value = "2026-10-17T12:34:56Z";
    const expected = new Intl.DateTimeFormat("zh-CN", {
      month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
      second: "2-digit", hour12: false,
    }).format(new Date(value));
    expect(formatTime(value)).toBe(expected);
  });
});
