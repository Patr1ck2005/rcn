// This fixture exercises the browser against the local member API contract.
// It models transfer receipts only; it is not a solver/scientific acceptance.
export async function memberApiFixture(page, options = {}) {
  const actor = { actor_id: "member-alice", roles: ["member", "machine_owner"] };
  let session = { connected: options.connected !== false, online: options.online !== false,
    remote_actions_available: options.online !== false, center_url: "https://compute.example.org", actor,
    connection_error: options.online === false ? { message: "中心暂时无法连接，可在本机暂停计算。" } : null };
  const operations = new Map();
  const calls = [];
  let jobsCreated = 0;
  let lostConfirm = options.lostConfirm === true;
  let lostUpload = options.lostUpload === true;
  const contributionOperations = new Map();
  let contribution = { configured: false, contribution_id: "11111111-2222-4333-8444-555555555555", revision: 0,
    work_root: "C:\\ProgramData\\ResearchComputeNetwork\\MemberNodes\\member-alice\\worker", preferences: {},
    ...(options.contribution || {}) };
  const preview = { project_id: "project-alice", profile_id: "comsol-6.4", submitter_id: actor.actor_id, input_count: 2, total_bytes: 2048, unit_count: options.missingPartition ? null : 2, estimated_duration_seconds: options.missingPartition ? null : 60, missing_fields: options.missingPartition ? ["requested_unit_count"] : [] };
  await page.route("**/v1/me/submission-policy", (route) => route.fulfill({ json: { person_id: actor.actor_id, policy: null, usage: {} } }));
  await page.route("**/v1/me/compute-credits", (route) => route.fulfill({ json: { person_id: actor.actor_id, available_cpu_core_hours: 0, available_gpu_device_hours: 0, reserved_cpu_core_hours: 0, reserved_gpu_device_hours: 0, settings: { metering_enabled: false } } }));
  await page.route("**/local/v1/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const method = request.method();
    const record = { pathname, method, headers: request.headers(), body: request.postData() };
    calls.push(record);
    const json = (value, status = 200) => route.fulfill({ status, json: value });
    if (pathname === "/local/v1/capabilities") return json({ mode: "member-client", schema_version: 1 });
    if (pathname === "/local/v1/agent-configurations") return json({ agents: [] });
    if (pathname === "/local/v1/session") {
      if (method === "POST") {
        const body = request.postDataJSON();
        session = { connected: true, online: true, remote_actions_available: true, center_url: body.center_url, actor }; return json(session);
      }
      if (method === "DELETE") { session = { connected: false, center_url: session.center_url }; return json(null, 200); }
      return json(session);
    }
    if (pathname === "/local/v1/packages") {
      if (options.damagedPackage) return json({ detail: "任务包校验失败：输入文件哈希不匹配" }, 422);
      if (options.foreignPackage) return json({ detail: "任务包提交身份与当前成员不匹配" }, 403);
      const original = [...operations.values()].filter((item) => item.package_id === "package-alice").at(-1);
      return json({ package_id: "package-alice", filename: decodeURIComponent(request.headers()["x-rcn-filename"]), preview,
        ...(original ? { operation_id: original.operation_id, operation: original } : {}) });
    }
    if (pathname === "/local/v1/operations") return json({ operations: [...operations.values()] });
    if (pathname === "/local/v1/contribution") return json(contribution);
    if (pathname.startsWith("/local/v1/contribution/operations/")) {
      const original = contributionOperations.get(pathname.split("/").at(-1));
      return json(original || { detail: { message: "original contribution absent", reason_code: "contribution_operation_not_found" } }, original ? 200 : 404);
    }
    if (pathname === "/local/v1/contribution/setup") {
      const payload = request.postDataJSON();
      const { invite, operation_id, expected_revision, ...preferences } = payload;
      contribution = { ...contribution, configured: true, machine_id: "MEMBER-ALICE", comsol_version: "6.4", revision: contribution.revision + 1,
        admission: { status: "科学验收进行中" }, work_root: payload.work_root, preferences: { ...preferences, paused: false } };
      const result = { ...contribution, operation: { operation_id, expected_revision, kind: "setup", actor_id: actor.actor_id,
        center_url: session.center_url, machine_id: "MEMBER-ALICE", payload_sha256: "a".repeat(64), status: "completed" }, result: contribution };
      contributionOperations.set(operation_id, result);
      return json(result);
    }
    if (pathname === "/local/v1/contribution/preferences") {
      const { operation_id, expected_revision, ...preferences } = request.postDataJSON();
      contribution = { ...contribution, revision: contribution.revision + 1, preferences: { ...contribution.preferences, ...preferences } };
      const result = { ...contribution, operation: { operation_id, expected_revision, kind: "preferences", actor_id: actor.actor_id,
        center_url: session.center_url, machine_id: contribution.machine_id, payload_sha256: "a".repeat(64), status: "completed" }, result: contribution };
      contributionOperations.set(operation_id, result);
      return json(result);
    }
    const match = pathname.match(/^\/local\/v1\/operations\/([^/]+)(?:\/(confirm|upload|collect|rerun))?$/);
    if (!match) return json({ detail: "unknown fixture route" }, 404);
    const [, id, action] = match;
    if (method === "PUT") {
      const body = request.postDataJSON();
      const operation = { operation_id: id, package_id: body.package_id, phase: "planned", preview: { ...preview, unit_count: body.requested_unit_count || preview.unit_count }, can_confirm: true };
      operations.set(id, operation); return json(operation);
    }
    let operation = operations.get(id);
    if (!operation) return json({ detail: "submission_not_found" }, 404);
    if (method === "GET") return json(operation);
    if (action === "confirm") {
      if (options.revoked) return json({ detail: { reason_code: "project_grant_revoked", message: "项目提交授权已撤销" } }, 403);
      if (!operation.job_id) {
        jobsCreated += 1;
        operation = { ...operation, phase: "confirmed", job_id: `job-alice-${jobsCreated}`, can_confirm: false, can_upload: true };
        operations.set(id, operation);
      }
      if (lostConfirm) { lostConfirm = false; return route.abort("connectionreset"); }
      return json(operation);
    }
    if (action === "upload") {
      operation = { ...operation, phase: "uploaded", can_upload: false, can_collect: true, job: { status: "completed", completed_units: operation.preview.unit_count, total_units: operation.preview.unit_count }, upload: { state: "completed", completed_files: 2, total_files: 2 } };
      operations.set(id, operation);
      if (lostUpload) { lostUpload = false; return route.abort("connectionreset"); }
      return json(operation);
    }
    if (action === "collect") {
      operation = { ...operation, phase: "collected", can_collect: false, collection: { state: "verified", verified_files: 2, total_files: 2, directory: `F:\\RCN-Member\\results\\${operation.job_id}` } };
      operations.set(id, operation); return json(operation);
    }
    if (action === "rerun") {
      const newId = request.postDataJSON().operation_id;
      const next = { operation_id: newId, package_id: operation.package_id, phase: "planned", preview: operation.preview, can_confirm: true };
      operations.set(newId, next); return json(next);
    }
    return json({ detail: "unknown action" }, 404);
  });
  return { calls, operations, jobsCreated: () => jobsCreated };
}

export async function selectTaskPackage(page) {
  await page.getByLabel("选择任务包", { exact: true }).setInputFiles({ name: "研究任务.zip", mimeType: "application/zip", buffer: Buffer.from("PK-member-api-browser-fixture") });
}
