import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import { DataLoadState } from "./AsyncState";

export default function DistributionStatus() {
  const [value, setValue] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const alive = useRef(false);
  const load = async () => {
    try {
      const identity = await api("/v1/release/identity");
      const contract = await api("/v1/distribution/contract");
      if (alive.current) { setValue({ identity, contract }); setError(""); }
    } catch (caught) { if (alive.current) setError(caught.message); }
  };
  useEffect(() => { alive.current = true; void load(); return () => { alive.current = false; }; }, []);
  const diagnostic = async () => {
    setBusy(true); setError("");
    try {
      const report = await api("/v1/admin/reliability-report");
      if (!alive.current) return;
      const object = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = object; link.download = "rcn-reliability-report.json";
      document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(object), 1000);
      setNotice("已生成脱敏诊断报告：不包含凭据、主机路径、原始错误文本和科学输入。仍含内部任务身份，请按课题组范围分享。");
    } catch (caught) { if (alive.current) setError(caught.message); }
    finally { if (alive.current) setBusy(false); }
  };
  return <section className="detail-section distribution-status" aria-label="分发与发行身份">
    <header><div><h2>分发与发行身份</h2><span>包版本、构建内容、生产部署与 Worker 是四个独立身份</span></div></header>
    {!value ? <DataLoadState label="正在读取发行信息" error={error} onRetry={load} /> : <>
      <dl className="distribution-identities">
        <div><dt>控制面部署</dt><dd><code>{value.identity.control_plane_deployment_id || "未标记"}</code></dd></div>
        <div><dt>包版本</dt><dd>{value.identity.package_version}</dd></div>
        <div><dt>内容构建 ID</dt><dd><code>{value.identity.build?.build_id || "旧包或源码运行：没有构建收据"}</code></dd></div>
        <div><dt>Worker 指纹</dt><dd><code>{value.identity.worker_runtime_version}</code></dd></div>
      </dl>
      {value.identity.build?.available && <p>构建树：<code>{value.identity.build.content_sha256}</code> · {value.identity.build.package_file_count} 个文件。
        {value.identity.build.source_dirty ? "构建时源码含未提交改动；以内容哈希核对。" : "源码提交信息保存在构建收据。"}
        完整性哈希不是机构代码签名，接口不会在每次刷新时重新哈希全部文件。</p>}
      <div className="distribution-boundaries">
        <article><h3>公共安装器</h3><p>可群发同一份已核验安装器和公开哈希；不内嵌个人邀请。</p></article>
        <article><h3>私密身份</h3><p>每人单独的邀请与登录令牌。本人项目授权、机主同意与机器凭据不能互换。</p></article>
        <article><h3>分层升级</h3><p>网页随控制面发布后刷新；客户端保留原身份；密封 Worker 另走批准与排空流程。</p></article>
      </div>
      <p>新显式计算邀请采用信任优先、科学验收异步；历史邀请仍按原策略处理。安装初始零容量不等于还要逐次人工审批。</p>
      {error && <p role="alert" className="inline-error">{error}</p>}
      {notice && <p role="status">{notice}</p>}
      <footer><button className="button" disabled={busy} onClick={diagnostic}>导出脱敏诊断报告</button>
        <button className="button" disabled={busy} onClick={load}>刷新发行身份</button></footer>
    </>}
  </section>;
}
