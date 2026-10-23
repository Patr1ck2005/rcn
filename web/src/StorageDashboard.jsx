import { useEffect, useState } from "react";
import { AlertTriangle, Archive, Database, HardDrive, Info } from "lucide-react";
import { storageBytes, storageDashboardModel, storageTime, nextStorageExpiry } from "./storageDashboardModel";
import "./StorageDashboard.css";

const roleName = (role) => ({ origin_spool: "Origin 中转", dispatcher_bundles: "派发输入包" }[role] || role || "角色未知");

function Metric({ label, value, detail }) {
  return <div><dt>{label}</dt><dd>{value}</dd>{detail && <small>{detail}</small>}</div>;
}

export default function StorageDashboard({ status = {}, inventory }) {
  const [, refreshExpiry] = useState(0);
  const now = Date.now();
  const model = storageDashboardModel(status, inventory, now);
  const expiresAt = nextStorageExpiry(inventory || status.inventory, now);
  useEffect(() => {
    if (expiresAt === null) return undefined;
    const timer = setTimeout(() => refreshExpiry((value) => value + 1), Math.max(0, expiresAt - Date.now()));
    return () => clearTimeout(timer);
  }, [expiresAt]);
  return <div className="storage-dashboard">
    <section className="detail-section storage-summary" aria-labelledby="storage-summary-title">
      <header><div><h2 id="storage-summary-title"><Database size={18} aria-hidden="true" />存储概况</h2><span>更新时间：{storageTime(model.generatedAt)}</span></div><span className={`storage-badge ${model.complete ? "" : "storage-badge-warning"}`}>{model.complete ? "登记回填完成" : "部分覆盖 / 回填待完成"}</span></header>
      <p>{model.coverage}</p>
      <p className="storage-explanation"><Info size={16} aria-hidden="true" />逻辑字节来自登记清单；硬链接可对应同一份物理数据。物理占用以卷采样为准，同卷多个根目录只展示一次容量。</p>
      <p>未归属的物理占用：<b>{storageBytes(model.unknownPhysicalBytes)}</b>。覆盖范围之外的设备占用不会记作已登记项目。</p>
      {status.write_pause && <p className="storage-alert" role="status"><AlertTriangle size={16} aria-hidden="true" />当前存储写入已暂停，请由管理员核对存储状态后接续。</p>}
    </section>

    <section className="detail-section" aria-labelledby="storage-volume-title">
      <header><div><h2 id="storage-volume-title">物理卷容量</h2><span>实际空闲 − 活跃容量承诺 − 10 GiB 硬保留 = 可用余量</span></div></header>
      <div className="storage-volume-grid">{model.volumes.map((volume, index) => <article className={`storage-volume ${volume.alert ? `storage-volume-${volume.alert}` : ""}`} key={`${volume.host_id}/${volume.volume_id}/${index}`}>
        <header><HardDrive size={19} aria-hidden="true" /><div><h3>{volume.volume_id || "物理卷身份未知"}</h3><small>{volume.host_id || "主机未知"}{volume.physical_device_id ? ` · 设备 ${volume.physical_device_id}` : " · 物理设备身份未知"}</small></div></header>
        {volume.alert && <p className="storage-alert" role="status"><AlertTriangle size={15} aria-hidden="true" />{volume.alert === "critical" ? "90% 软告警" : "80% 软告警"}：卷已用 {volume.usedPercent.toFixed(1)}%</p>}
        {volume.usedPercent !== null ? <><div className="storage-capacity-track" role="meter" aria-label={`${volume.volume_id || "卷"}已用容量`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Number(volume.usedPercent.toFixed(1))}><span style={{ width: `${volume.usedPercent}%` }} /></div><p className="storage-capacity-caption">已用 {volume.usedPercent.toFixed(1)}% · 总容量 {storageBytes(volume.total_bytes)}</p></> : <p className="storage-muted">物理容量未知</p>}
        <dl className="storage-metrics"><Metric label="实际空闲" value={storageBytes(volume.free_bytes)} /><Metric label="活跃容量承诺" value={storageBytes(volume.reserved_bytes)} /><Metric label="硬保留" value={storageBytes(volume.hard_reserve_bytes)} /><Metric label="可用余量" value={storageBytes(volume.usable_bytes)} /></dl>
        <div className="storage-forecast"><b>按正常登记文件的小时净增长估计</b>{volume.forecast.known ? <p>净增长 {storageBytes(volume.forecast.growth)} / 天 · 约 {volume.forecast.days.toLocaleString("zh-CN", { maximumFractionDigits: 1 })} 天后达到保留线</p> : <p>耗尽时间：未知 · {volume.forecast.reason}</p>}<small>依据逻辑文件事件，未登记占用不在预测范围。{volume.sample_count ?? "未知"} 个小时桶 · 采样于 {storageTime(volume.sampled_at)}{volume.stale ? " · 已过期" : ""}</small></div>
      </article>)}</div>
      {!model.volumes.length && <p className="empty-copy">尚无可用的物理卷采样。容量与耗尽时间均未知。</p>}
      <p className="storage-muted">80% / 90% 为物理已用比例的提示阈值；实际可用余量仍受活跃承诺和硬保留约束。</p>
      {model.roots.length > 0 && <details className="storage-roots"><summary>已登记根目录与可用性</summary><dl>{model.roots.map((root) => <div key={root.role}><dt>{roleName(root.role)}</dt><dd><b>{root.available === true ? "可用" : root.available === false ? "不可用" : "未知"} · {root.registered ? "已登记" : "未登记"}</b><code>{root.root || "根目录未知"}</code>{root.reason_code && <small>{root.reason_code}</small>}</dd></div>)}</dl></details>}
    </section>

    <section className="detail-section" aria-labelledby="storage-project-title">
      <header><div><h2 id="storage-project-title">项目与角色账目</h2><span>逻辑登记量；已确认退役依据删除回执，不等同于物理释放量</span></div></header>
      <div className="storage-table-wrap" role="region" aria-label="项目存储账目，可横向滚动" tabIndex={0}><table className="storage-table"><caption className="storage-sr-only">各项目、角色和位置的逻辑字节状态与独立物理盘点</caption><thead><tr><th scope="col">项目 / 角色 / 位置</th><th scope="col">逻辑登记</th><th scope="col">盘点物理占用</th><th scope="col">待托管</th><th scope="col">符合退役条件</th><th scope="col">已确认退役</th></tr></thead><tbody>{model.projects.map((row, index) => <tr key={`${row.project_id}/${row.role}/${row.location}/${index}`}><th scope="row"><b>{row.project_id || "项目未知"}</b><small>{roleName(row.role)} · {row.location || "位置未知"}</small></th><td>{storageBytes(row.logical)}</td><td>{storageBytes(row.physical)}{typeof row.registered_files === "number" && <small>已盘点 {row.measured_files ?? 0} / {row.registered_files} 个文件</small>}{row.occupancy_oldest_observed_at && <small>最早采样 {storageTime(row.occupancy_oldest_observed_at)}{row.occupancy_stale ? " · 已过期" : ""}</small>}</td><td>{storageBytes(row.pending)}</td><td>{storageBytes(row.eligible)}</td><td>{storageBytes(row.retired)}</td></tr>)}</tbody></table></div>
      {!model.projects.length && <p className="empty-copy">尚无项目登记快照。未知账目不会显示为零。</p>}
      <p className="storage-muted">这些状态可能重叠，不相加为总占用。物理盘点只读取已登记文件的占用信息；硬链接按原生文件身份去重，并归到首次登记的位置。未盘点或过期的范围显示未知，未登记文件和其他程序占用仍以卷容量为准。</p>
    </section>

    <section className="detail-section storage-continuation" aria-labelledby="storage-archive-title"><header><div><h2 id="storage-archive-title"><Archive size={18} aria-hidden="true" />归档取回与接续</h2><span>浏览账目只读取元数据</span></div></header><p>需要归档结果时，请在本地客户端或来源项目 Agent 中发起取回，选择已登记的最终接收位置，并沿原操作核对进度与回执。</p>{model.continuations.length > 0 && <ul>{model.continuations.map((operation, index) => <li key={operation.operation_id || operation.request_id || index}><b>{operation.operation_id || operation.request_id || "操作标识未知"}</b><span>{operation.state || "状态未知"}</span>{operation.next_action && <p>{operation.next_action}</p>}</li>)}</ul>}</section>
  </div>;
}
