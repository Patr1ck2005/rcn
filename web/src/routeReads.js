export function routeResources(pathname) {
  const resources = pathname === "/app/overview"
    ? { me: "/v1/me", settings: "/v1/settings/features" }
    : { overview: "/v1/overview", me: "/v1/me", settings: "/v1/settings/features" };
  if (["/app/map", "/app/operations"].includes(pathname)) resources.dispatcher = "/v1/dispatcher/status";
  if (pathname === "/app/operations") resources.metrics = "/v1/operations/metrics";
  return { resources, jobs: pathname === "/app/runs" ? "history" : pathname === "/app/map" ? "current" : null };
}

export function eventAffectsRoute(pathname, event) {
  const type = `${event?.subject_type || ""} ${event?.event_type || ""}`;
  const jobId = pathname.match(/^\/app\/runs\/([^/]+)/)?.[1];
  if (jobId && /job|unit|attempt|artifact|collection/.test(type)) {
    const affectedJob = event.details?.job_id || (event.subject_type === "job" ? event.subject_id : null);
    return !affectedJob || decodeURIComponent(jobId) === affectedJob;
  }
  const machineId = pathname.match(/^\/app\/machines\/([^/]+)/)?.[1];
  if (machineId && event.subject_type === "machine") return decodeURIComponent(machineId) === event.subject_id;
  if (/job|unit|attempt|artifact|collection/.test(type)) return /^\/app\/(overview|fleet|machines|compare|runs|map|operations|alerts)/.test(pathname);
  if (/machine|telemetry|pressure|capacity|runtime/.test(type)) return /^\/app\/(overview|fleet|machines|compare|map|runs|operations|control|alerts|admin)/.test(pathname);
  if (/dispatcher|control/.test(type)) return /^\/app\/(overview|fleet|machines|compare|map|operations|control|alerts|admin)/.test(pathname);
  return true;
}

export function eventResources(event) {
  const type = `${event?.subject_type || ""} ${event?.event_type || ""}`;
  // These settings can change visibility and which details are authorized.
  if (/feature_settings|visibility/.test(type)) return null;
  if (/compute_credit|credit|person_submission_policy/.test(type)) return ["personal-access", "credits"];
  if (/job|unit|attempt|artifact|collection/.test(type)) return ["overview", "jobs", "insights", "job-detail", "machine-detail", "alerts", "metrics"];
  if (/dispatcher|control/.test(type)) return ["overview", "dispatcher", "control-runs", "machines", "machine-detail", "metrics", "insights", "executionRuntime", "preflights"];
  if (/machine|telemetry|pressure|capacity|runtime/.test(type)) return ["overview", "machines", "machine-detail", "jobs", "insights", "alerts", "control-runs", "metrics", "onboarding", "preflights", "enrollments", "executionRuntime"];
  if (/project/.test(type)) return ["overview", "projects", "projectRegistrations", "jobs", "insights", "personal-access"];
  if (/enrollment|invitation|onboarding|preflight/.test(type)) return ["overview", "enrollments", "onboarding", "preflights", "machines", "machine-detail"];
  if (/user|role|token|auth/.test(type)) return null;
  if (/profile|approval|policy|settings/.test(type)) return ["overview", "settings", "profiles", "approvals", "templateEnvironments", "projects", "personal-access", "jobs", "insights", "machine-detail", "control-runs"];
  return null; // Unknown event types remain conservative full invalidations.
}
