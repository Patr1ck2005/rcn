export const operationLabels = {
  imported: "任务包已校验", planned: "等待确认", planning: "正在规划", confirming: "正在提交",
  confirmed: "等待上传", uploading: "正在上传", uploaded: "等待计算", submitted: "等待计算", queued: "排队",
  assigned: "已派发", prepared: "已预备", running: "计算中", finalizing: "导出中",
  collecting: "正在下载", collected: "结果已核验", completed: "计算完成", failed: "需要处理",
  failed_terminal: "计算失败", failed_retriable: "等待重试", cancelled: "已取消", unknown: "等待恢复查询",
  "planning-unknown": "规划等待恢复", "confirm-unknown": "提交等待恢复", "upload-interrupted": "上传中断", "collection-interrupted": "下载中断",
};

export function operationLabel(operation) {
  const recovery = operation.collection_control?.state;
  if (recovery === "user_paused") return "结果下载已暂停";
  if (recovery === "retry_wait") return "等待自动续传";
  if (recovery === "fault_paused") return "下载需要处理";
  if (operation.phase === "collection-waiting" || recovery === "waiting") return "等待结果下载";
  if ((operation.collection?.stage || operation.collection?.state) === "restore_pending") return "等待归档取回";
  const phase = ["verified", "complete", "completed"].includes(operation.collection?.state) ? "collected"
    : ["uploaded", "submitted"].includes(operation.phase) && operation.job?.status ? operation.job.status : operation.phase;
  return operationLabels[phase] || phase || "等待确认";
}

export function collectionProgress(operation) {
  const progress = operation.collection;
  if (!progress) return progress;
  const states = { user_paused: "paused", retry_wait: "retry_wait", fault_paused: "conflict", waiting: "waiting" };
  const stage = states[operation.collection_control?.state] || (operation.phase === "collection-waiting" ? "waiting" : null);
  return stage ? { ...progress, stage, message: "" } : progress;
}

export function operationActions(operation) {
  const hasJob = Boolean(operation.job_id || operation.job?.job_id);
  const uploaded = ["uploaded", "complete", "completed"].includes(operation.upload?.state)
    || ["uploaded", "running", "completed", "collected"].includes(operation.phase);
  const verified = ["verified", "complete", "completed"].includes(operation.collection?.state) || operation.phase === "collected";
  const completed = operation.job?.status === "completed" || operation.phase === "completed";
  return {
    hasJob,
    canConfirm: operation.can_confirm ?? !hasJob,
    canUpload: operation.can_upload ?? (hasJob && !uploaded && operation.upload?.state !== "uploading"),
    canCollect: !verified && (operation.can_collect ?? (completed && operation.collection?.state !== "collecting")),
    verified,
    canPauseCollection: !verified && ["active", "retry_wait", "waiting"].includes(operation.collection_control?.state),
  };
}

export function requiresUnitCount(preview = {}) {
  if (Array.isArray(preview.missing_fields)) return preview.missing_fields.some((field) => ["requested_unit_count", "unit_count", "partitioning"].includes(field));
  if (preview.atomic_item_count === 1) return false;
  return preview.missing_fields?.some((field) => ["requested_unit_count", "unit_count", "partitioning"].includes(field))
    || (preview.estimated_duration_seconds == null && !preview.unit_count);
}

export function validateUnitCount(value) {
  const units = Number(value);
  if (!Number.isSafeInteger(units) || units < 1) throw new Error("请填写大于零的整数单元数");
  return units;
}

// A mutation may have completed even when its HTTP response was lost. Recover
// its durable local record; never turn an unknown result into another Job.
export async function mutateAndRecover(request, operationId, action, body) {
  const base = `/local/v1/operations/${encodeURIComponent(operationId)}`;
  try {
    return await request(`${base}/${action}`, { method: "POST", ...(body ? { body: JSON.stringify(body) } : {}) });
  } catch (error) {
    if (error.status >= 400 && error.status < 500) throw error;
    try {
      return { ...await request(base), recovery_notice: "响应中断，已恢复原提交记录。" };
    } catch {
      error.message = `${error.message || "连接中断"}。原提交编号已保留，请恢复查询后继续。`;
      throw error;
    }
  }
}
