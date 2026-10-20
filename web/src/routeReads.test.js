import { describe, expect, it } from "vitest";
import { eventAffectsRoute, eventResources, routeResources } from "./routeReads";

describe("route read budgets", () => {
  it("leaves Overview's snapshot to Insights while Runs retains its Fleet data", () => {
    expect(routeResources("/app/overview").resources).toEqual({ me: "/v1/me", settings: "/v1/settings/features" });
    expect(routeResources("/app/runs").resources.overview).toBe("/v1/overview");
    expect(routeResources("/app/fleet").resources.overview).toBe("/v1/overview");
  });
  it("reads history only on Runs, current work on Map and metrics on Operations", () => {
    for (const route of ["overview", "fleet", "projects", "control", "admin", "runs/job-old"]) {
      const reads = routeResources(`/app/${route}`);
      expect(reads.jobs).toBeNull();
      expect(reads.resources.metrics).toBeUndefined();
    }
    expect(routeResources("/app/runs").jobs).toBe("history");
    expect(routeResources("/app/map").jobs).toBe("current");
    expect(routeResources("/app/operations").resources.metrics).toBe("/v1/operations/metrics");
  });
  it("invalidates only pages affected by a known job or machine event", () => {
    const job = { subject_type: "job", subject_id: "job-a", event_type: "job.updated" };
    expect(eventAffectsRoute("/app/projects", job)).toBe(false);
    expect(eventAffectsRoute("/app/runs", job)).toBe(true);
    expect(eventAffectsRoute("/app/fleet", job)).toBe(true);
    expect(eventAffectsRoute("/app/machines/A", job)).toBe(true);
    expect(eventAffectsRoute("/app/runs/job-b", job)).toBe(false);
    expect(eventAffectsRoute("/app/runs/job-a", job)).toBe(true);
    expect(eventAffectsRoute("/app/machines/B", { subject_type: "machine", subject_id: "A" })).toBe(false);
    expect(eventAffectsRoute("/app/projects", { event_type: "person_submission_policy.updated" })).toBe(true);
  });
  it("targets changed sources while permission and unknown events retain full revalidation", () => {
    const job = eventResources({ subject_type: "job", event_type: "job.updated" });
    expect(job).toEqual(expect.arrayContaining(["overview", "jobs", "insights"]));
    expect(job).not.toContain("me"); expect(job).not.toContain("settings"); expect(job).not.toContain("profiles");
    expect(eventResources({ event_type: "person_submission_policy.updated" })).toEqual(["personal-access", "credits"]);
    expect(eventResources({ event_type: "feature_settings.updated" })).toBeNull();
    expect(eventResources({ event_type: "user.roles_updated" })).toBeNull();
    expect(eventResources({ event_type: "new.future_event" })).toBeNull();
    expect(eventResources({ subject_type: "machine", event_type: "runtime.promoted" })).toContain("onboarding");
  });
});
