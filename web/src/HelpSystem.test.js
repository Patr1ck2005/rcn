import { describe, expect, it } from "vitest";

import { filterHelpArticles, helpArticlePath, helpTopics, normalizeHelpReturn } from "./HelpSystem";

describe("help system", () => {
  const articles = [
    { slug: "architecture", title: "架构与边界", summary: "控制面与成员节点", keywords: ["Dispatcher"] },
    { slug: "job-lifecycle", title: "任务生命周期", summary: "排队、运行与回收", keywords: ["ETA", "Attempt"] },
  ];

  it("searches title, summary and keywords without inventing results for an empty query", () => {
    expect(filterHelpArticles(articles, "dispatcher").map((item) => item.slug)).toEqual(["architecture"]);
    expect(filterHelpArticles(articles, "回收").map((item) => item.slug)).toEqual(["job-lifecycle"]);
    expect(filterHelpArticles(articles, " ")).toEqual([]);
  });

  it("maps every contextual entry to a help slug and a focus hint", () => {
    for (const topic of Object.values(helpTopics)) {
      expect(topic.slug).toMatch(/^[a-z0-9-]+$/);
      expect(topic.title.length).toBeGreaterThan(0);
      expect(topic.hint.length).toBeGreaterThan(8);
    }
  });

  it("builds standalone and embedded article paths", () => {
    expect(helpArticlePath("architecture")).toBe("/help/architecture");
    expect(helpArticlePath("architecture", true)).toBe("/app/help/architecture");
    expect(helpArticlePath(null, true)).toBe("/app/help");
  });

  it("accepts only safe connect and non-help app return targets", () => {
    expect(normalizeHelpReturn({ path: "/connect", scrollY: -2 })).toMatchObject({ kind: "connect", path: "/connect", scrollY: 0 });
    expect(normalizeHelpReturn({ path: "/app/fleet?q=office#gpu", scrollY: 140 })).toMatchObject({ kind: "app", path: "/app/fleet?q=office#gpu", scrollY: 140 });
    expect(normalizeHelpReturn({ path: "/app/help/architecture" })).toBeNull();
    expect(normalizeHelpReturn({ path: "https://example.test/app/fleet" })).toBeNull();
  });
});
