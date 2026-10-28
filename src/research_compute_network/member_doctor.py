"""Bounded, secret-free member diagnostics shared by the UI and Agent CLI."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
from uuid import uuid4

from . import member_registration as storage
from .client import RcnApiError


ERRORS = {
    "member_client_port_in_use_by_another_service": ("port", "客户端端口被其他程序占用", "关闭占用该端口的程序后重新打开客户端；不会自动终止其他进程。"),
    "member_credentials_dpapi_failed": ("identity", "当前 Windows 用户无法解密原登录", "使用原 Windows 用户登录，或导入本人的接入包重新连接；原任务保留。"),
    "member_credentials_invalid": ("identity", "本机登录记录无法读取", "重新导入本人的接入包；不要删除任务和结果目录。"),
    "member_credentials_unavailable": ("identity", "本机登录暂时不可用", "导入本人的接入包，或将诊断交给本机 Agent。"),
    "registration_root_permissions": ("local_identity", "客户端目录权限不符合当前用户身份", "确认当前 Windows 用户；使用原安装器修复客户端，不递归修改其他目录权限。"),
    "registration_file_permissions": ("local_identity", "连接文件权限需要恢复", "用原 Windows 用户导入接入包；保留原身份和结果。"),
    "member_connection_owner_or_root_changed": ("local_identity", "连接记录属于其他用户或旧目录", "导入本人的可迁移接入包；不要复制别人的本机配置。"),
    "member_connection_pinned_file_changed": ("connection", "连接文件与登记校验值不一致", "重新导入管理员提供的本人接入包。"),
    "member_connection_spec_required": ("connection", "尚未配置中心连接", "导入个人接入包，或在高级入口填写 HTTPS 地址。"),
    "member_openssh_missing": ("ssh", "尚未安装 SSH 客户端", "点击恢复本机连接以安装 Windows OpenSSH Client；可能需要网络和管理员确认。"),
    "member_openssh_restart_required_rerun_original_installer": ("ssh", "Windows 组件需要重启后完成", "保存自己的工作，重启后继续原接入操作；客户端不会自动重启。"),
    "member_openssh_installation_outcome_pending": ("ssh", "Windows 组件安装仍待确认", "稍后重新检查；继续原安装，不重复启动。"),
    "member_openssh_supply_unconfirmed_preserve_state": ("ssh", "Windows 组件尚未安装完成", "检查 Windows 更新或管理员确认结果，再点击恢复本机连接。"),
    "center_login_required": ("login", "个人登录已失效或被撤销", "重新导入当前有效的个人接入包；网络重试不能恢复已撤销的凭据。"),
    "center_permission_denied": ("submission", "当前身份尚未获得所需提交权限", "让管理员确认本人的提交策略，诊断中保留错误码即可，无需发送 token。"),
    "center_unavailable": ("center", "暂时无法连接中心", "检查网络后重新检查；保留本机任务与下载进度。"),
    "member_connection_unavailable": ("connection", "受管连接尚未建立", "重新检查连接，或重新导入本人的接入包。"),
    "member_agent_launcher_unavailable": ("agent", "Agent 稳定入口尚未就绪", "使用同一 Setup 修复安装，再在客户端重新导出 Agent 配置。"),
    "member_installation_integrity_failed": ("installation", "安装文件未通过完整性核验", "从管理员给出的同一发行版本重新安装；身份与结果保留。"),
    "agent_submission_not_eligible": ("submission", "个人提交准入尚未启用或已暂停", "请管理员核对本人的提交策略与获授权 Profile，再继续原 Agent 实例。"),
    "submission_person_not_active_member": ("submission", "当前账号不是可提交任务的有效成员", "请管理员核对本人的成员身份；无需再索取第二份 token。"),
    "personal_login_required": ("login", "此操作需要个人登录", "在成员客户端导入本人的个人接入包，再配置 Agent；Agent 凭据不能创建其他凭据。"),
    "inactive_token_owner": ("login", "成员身份已停用", "请管理员核对本人身份状态，保留原任务和结果。"),
    "agent_credential_content_conflict": ("agent", "此 Agent 编号已绑定不同内容", "保留原实例名称与类型，刷新并继续原记录；只有明确新建 Agent 才使用新编号。"),
    "agent_credential_hash_already_bound": ("agent", "此凭据已绑定其他实例", "保留原加密记录并导出诊断，由本机 Agent 核对原实例；不要复制凭据文件。"),
    "agent_credential_not_found": ("agent", "当前成员找不到该 Agent 实例", "确认当前个人身份和原实例编号，再重新检查；不要混用其他成员配置。"),
    "invalid_agent_credential_request": ("agent", "Agent 登记信息不符合当前接口", "使用新版客户端继续原实例；不要手工修改凭据摘要。"),
}

# Fixed allowlists keep diagnoses actionable without reflecting input, paths or
# remote exception text back into the UI/exported report.
for _codes, _stage, _message, _action in (
    ("invalid_bundle archive_entries bundle_size invalid_manifest manifest_hash invalid_connection invalid_known_hosts invalid_personal_token invalid_ssh_identity invalid_build_input", "package", "接入包不完整或内容校验失败", "请管理员重新生成本人接入包；不要解压修改包内文件。"),
    ("different_member personal_identity_mismatch", "identity", "接入包身份与当前成员不符", "确认收到的是本人的接入包；原连接和任务已保留。"),
    ("different_center center_trust_changed existing_trust_unselected", "connection", "接入包指向不同中心或中心身份已改变", "请管理员核对中心身份；客户端不会自动合并不同中心的数据。"),
    ("ssh_prerequisite_required", "ssh", "尚未安装 Windows SSH 客户端", "点击恢复本机连接补齐 OpenSSH Client，然后继续原接入编号；可能需要联网和管理员确认。"),
    ("upstream_collides_with_broker", "port", "接入包端口与客户端冲突", "请管理员重新生成使用其他转发端口的接入包。"),
    ("operations_busy", "connection", "当前任务或下载仍在执行", "等待本机传输完成后继续原接入编号，不需重新导入。"),
    ("not_found invalid_identifier invalid_journal journal_changed journal_size migration_journal_changed migration_root_changed migration_size local_state_changed commit_failed staged_file_changed staged_channel_changed existing_channel_changed existing_connection_changed agent_binding_changed owner_or_root_changed root_not_owned desktop_root_required channel_children_changed legacy_handoff_pending_or_changed", "local_identity", "本机接入记录发生变化，原数据已保留", "点击重新检查并将诊断交给本机 Agent；不要删除原任务、下载或身份目录。"),
    ("validation_failed", "connection", "接入包连接验证尚未通过", "检查网络后继续原接入编号；仍失败时将错误码交给 Agent。"),
):
    for _code in _codes.split():
        ERRORS["member_connection_import_" + _code] = (_stage, _message, _action)

for _codes, _stage, _message, _action in (
    ("upstream_port_in_use upstream_listener_not_owned", "port", "转发端口正被其他连接占用", "先结束已确认属于旧客户端的连接，或让管理员提供其他端口；客户端不会终止未知程序。"),
    ("channel_start_pending process_missing", "connection", "SSH 通道尚未建立", "检查网络和中心后点击恢复本机连接；继续原操作。"),
    ("reference_changed channel_spec_changed channel_receipt_changed channel_owner_changed process_identity_changed handoff_spec_changed legacy_port_changed legacy_task_check_failed legacy_source_not_reviewed legacy_root_changed member_identity_changed legacy_process_not_owned legacy_children_changed legacy_ssh_not_owned legacy_listener_changed legacy_listener_not_owned legacy_startup_pin_required legacy_task_not_owned legacy_task_identity_changed legacy_process_still_draining legacy_listener_still_present", "local_identity", "原连接身份或状态已改变", "重新导入本人的接入包，或将诊断交给本机 Agent；原结果保留。"),
    ("https_required https_spec_invalid ssh_spec_invalid absolute_path_required mode_unselected reference_required member_identity_required", "connection", "本机连接描述不完整", "导入管理员生成的个人接入包；高级手工入口需要完整 HTTPS 地址。"),
):
    for _code in _codes.split():
        ERRORS["member_connection_" + _code] = (_stage, _message, _action)

for _suffix, _existing in {
    "center_login_required": "center_login_required", "center_permission_denied": "center_permission_denied",
    "center_unavailable": "center_unavailable", "upstream_port_in_use": "member_connection_upstream_port_in_use",
    "pinned_file_changed": "member_connection_pinned_file_changed", "pinned_file_missing": "member_connection_pinned_file_changed",
    "channel_not_owned": "member_connection_channel_owner_changed", "ssh_channel_unavailable": "member_connection_channel_start_pending",
    "local_secret_unavailable": "member_credentials_unavailable", "local_permissions_invalid": "registration_file_permissions",
}.items():
    ERRORS["member_connection_import_" + _suffix] = ERRORS[_existing]


def error_detail(exc, *, stage="connection"):
    code = getattr(exc, "reason_code", None) or getattr(exc, "reason", None)
    # Only recognized literal codes may cross the diagnostic boundary.
    literal = str(exc)
    if not code and literal in ERRORS:
        code = literal
    if isinstance(exc, RcnApiError) and code not in ERRORS:
        if exc.status == 401:
            code = "center_login_required"
        elif exc.status == 403:
            code = "center_permission_denied"
        elif not code:
            code = "center_unavailable"
    if code not in ERRORS:
        code = "center_unavailable" if stage == "center" else "member_connection_unavailable"
    resolved_stage, message, action = ERRORS[code]
    return {"stage": resolved_stage, "status": "failed", "reason_code": code,
            "message": message, "next_action": action, "help_slug": "member-getting-started"}


def _check(stage, status, message, *, code=None, action=None):
    return {"stage": stage, "status": status, "reason_code": code,
            "message": message, "next_action": action, "help_slug": "member-getting-started"}


def installed_integrity():
    from .member_client_installer import verify_snapshot
    release = Path(sys.executable).absolute().parents[2]
    if not (release / "member-software-release.json").is_file():
        return _check("installation", "skipped", "当前为开发或旧版命令环境，未宣称安装包完整性已验证。")
    try:
        verify_snapshot(release)
    except (ValueError, RuntimeError, OSError):
        return error_detail(RuntimeError("member_installation_integrity_failed"))
    return _check("installation", "passed", "已安装文件与发行清单一致。")


def diagnose(broker, *, repair=False, verify_install=True):
    """One call, one channel resolution. Never submits work or grants compute."""
    checks = [installed_integrity()] if verify_install else []
    try:
        storage._private_directory(broker.root, create=False)
        checks.append(_check("local_identity", "passed", "本机客户端目录属于当前用户。"))
    except (RuntimeError, ValueError, OSError) as exc:
        checks.append(error_detail(exc, stage="local_identity"))
        return _result(checks)
    initial = getattr(broker, "credential_error", None)
    if initial:
        checks.append(error_detail(RuntimeError(initial), stage="identity"))
    if repair:
        # Restoring a selected managed channel already uses exact process identity
        # and idempotent reuse in the existing resolver. No process is killed here.
        from .member_client_connection import load_spec
        try:
            from .member_connection_bundle import pending_import, confirm_import
            pending = pending_import(broker) if (broker.root / "connection-imports").is_dir() else None
            if pending and pending["state"] == "failed" and pending.get("reason_code") == "member_connection_import_ssh_prerequisite_required":
                from .member_openssh_prerequisite import ensure_member_ssh_client
                ensure_member_ssh_client(state_root=broker.root, accept_supply=True)
                confirm_import(broker, pending["import_id"])
                checks.append(_check("ssh", "passed", "SSH 客户端已就绪，已继续原接入操作。"))
            loaded = load_spec(broker.root)
            if loaded and loaded[0].mode == "managed-ssh":
                executable = Path(loaded[0].ssh.executable.path)
                if not executable.is_file():
                    from .member_openssh_prerequisite import ensure_member_ssh_client
                    ensure_member_ssh_client(state_root=broker.root, accept_supply=True)
        except (RuntimeError, ValueError, OSError) as exc:
            checks.append(error_detail(exc, stage="ssh"))
    if not broker.login:
        checks.append(_check("login", "warning", "尚未登录个人身份。", code="member_connection_spec_required",
                             action="导入个人接入包，连接成功后配置 Agent。"))
        checks.append(_check("submission", "skipped", "登录后检查提交权限。"))
        return _result(checks)
    try:
        api, descriptor = broker._api_with_connection(broker.login["center_url"], broker.login["token"])
        checks.append(_check("connection", "passed", "中心连接已解析并核验。"))
        actor = api.current_actor()
        if actor.get("actor_id") != (broker.login.get("actor") or {}).get("actor_id"):
            raise RuntimeError("member_connection_owner_or_root_changed")
        checks.append(_check("login", "passed", "中心已确认当前个人身份。"))
        view = api._request("GET", "/v1/me/submission-policy")
        policy = view.get("policy") if isinstance(view, dict) else None
        enabled = bool(isinstance(policy, dict) and policy.get("approved") and not policy.get("paused")
                       and policy.get("max_queued_units", 0) > 0 and policy.get("max_running_units", 0) > 0
                       and policy.get("allowed_profiles"))
        legacy = isinstance(view, dict) and view.get("source") == "legacy_project_grants"
        checks.append(_check("submission", "passed" if enabled else "warning",
            "已确认个人提交策略启用；具体任务仍按项目和 Profile 检查。" if enabled else
            "当前按项目授权；请用任务预览检查具体项目和 Profile。" if legacy else "本人的提交策略暂未启用。",
            action=None if enabled else "先预览获授权项目的任务包。" if legacy else "请管理员确认本人的提交授权。"))
    except (RcnApiError, RuntimeError, ValueError, OSError) as exc:
        checks.append(error_detail(exc, stage="center"))
    # Do not refresh authentication a second time just to enumerate local profiles.
    directory = broker.root / "agents"
    count = len(list(directory.glob("*/agent-profile.json"))) if directory.is_dir() else 0
    checks.append(_check("agent", "passed" if count else "warning",
        f"本机已有 {count} 个 Agent 配置。" if count else "尚未配置 Agent。",
        action=None if count else "在连接与 Agent 配置页选择 Agent，点击一键配置。"))
    return _result(checks)


def _result(checks):
    failed = [c for c in checks if c["status"] == "failed"]
    return {"schema_version": 1, "diagnostic_id": str(uuid4()),
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "ok": not failed and not any(c["stage"] == "login" and c["status"] != "passed" for c in checks),
            "summary": "请按下面的步骤完成连接。" if failed else "检查完成，请查看各阶段状态。",
            "checks": checks, "next_actions": list(dict.fromkeys(c["next_action"] for c in checks if c.get("next_action"))),
            "secrets_included": False, "compute_started": False}
