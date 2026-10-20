"""Secret-free Agent configuration exported by the local member wizard."""
from __future__ import annotations

import base64
import hashlib
from io import BytesIO
import json
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Literal
from uuid import UUID
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, SecretStr

from . import member_registration as storage
from .member_client_credentials import PersonalCredentialStore


class MemberAgentExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: Literal["codex", "claude", "dsh"]
    agent_id: UUID
    label: str | None = None
    token: SecretStr | None = None


AGENT_TARGETS = {
    "codex": ("Codex", "AGENTS.md"),
    "claude": ("Claude Code", "CLAUDE.md"),
    "dsh": ("DSH", "AGENTS.md"),
}


def _profile_path(broker, agent_id):
    identifier = str(UUID(str(agent_id)))
    return broker.root / "agents" / identifier / "agent-profile.json"


def _read_profile(path):
    from .member_client import _read_json
    storage._unlinked(path)
    profile = _read_json(path)
    if (profile.get("schema_version") != 1 or profile.get("agent_id") != path.parent.name
            or profile.get("target") not in AGENT_TARGETS
            or not isinstance(profile.get("label"), str)
            or not isinstance(profile.get("credential_fingerprint"), str)):
        raise HTTPException(409, "本机 Agent 配置记录未通过校验")
    return profile


def _present_profile(profile, root):
    return {key: profile[key] for key in ("agent_id", "actor_id", "center_url", "target", "label")} | {
        "credential_id": profile.get("credential_id"),
        "configured": (root / "credentials" / "personal-login.dpapi").is_file()}


def list_member_agent_configs(broker):
    session = broker.session()
    actor = (session.get("actor") or {}).get("actor_id")
    if not actor:
        raise HTTPException(401, "请先连接个人身份")
    profiles = []
    with broker.lock:
        directory = broker.root / "agents"
        storage._unlinked(directory)
        for path in sorted(directory.glob("*/agent-profile.json")):
            profile = _read_profile(path)
            if profile["actor_id"] == actor and profile["center_url"] == session["center_url"]:
                profiles.append(_present_profile(profile, path.parent))
    return {"agents": profiles}


def clear_member_agent_login(broker, agent_id):
    """Remove only this local encrypted credential; no center revocation claim."""
    session = broker.session()
    with broker.lock:
        path = _profile_path(broker, agent_id)
        if not path.is_file():
            raise HTTPException(404, "本机 Agent 配置不存在")
        profile = _read_profile(path)
        if (profile["actor_id"] != (session.get("actor") or {}).get("actor_id")
                or profile["center_url"] != session.get("center_url")):
            raise HTTPException(403, "本机 Agent 配置属于另一位成员")
        store = PersonalCredentialStore(path.parent / "credentials")
        if store.path.exists():
            store.clear()
    return {"agent_id": profile["agent_id"], "local_login_removed": True,
            "center_token_revoked": False,
            "next_action": "如需撤销中心凭据，请让管理员按原签发记录单独撤销此 Agent token。"}


def _agent_view(broker, session, target, agent_id, label, token):
    """Bind one pre-issued restricted token to its own DPAPI/operation root."""
    from .member_client import _write_json
    path = _profile_path(broker, agent_id)
    root = path.parent
    profile = _read_profile(path) if path.exists() else None
    if profile and (profile["actor_id"] != session["actor"]["actor_id"]
                    or profile["center_url"] != session["center_url"] or profile["target"] != target):
        raise HTTPException(403, "本机 Agent 配置与当前身份不一致")
    if profile and label is not None and label.strip() != profile["label"]:
        raise HTTPException(409, "请沿用此 Agent 的原始名称")
    if not profile and (not isinstance(label, str) or not 1 <= len(label.strip()) <= 80
                        or any(ord(character) < 32 or ord(character) == 127 for character in label)):
        raise HTTPException(422, "请填写不超过 80 字符的 Agent 名称")
    if token is not None:
        token = token.strip()
        if not 1 <= len(token) <= 4096 or not token.isascii():
            raise HTTPException(422, "请提供此 Agent 独立签发的 token")
        if secrets.compare_digest(token, broker.login["token"]):
            raise HTTPException(422, "Agent 必须使用独立 token，不能复用桌面个人登录")
        fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if profile and profile["credential_fingerprint"] != fingerprint:
            raise HTTPException(409, "此 Agent 已绑定另一份独立凭据；新凭据请新建 Agent 实例")
        for other in (broker.root / "agents").glob("*/agent-profile.json"):
            known = _read_profile(other)
            if (known["agent_id"] != root.name and known["actor_id"] == session["actor"]["actor_id"]
                    and known["center_url"] == session["center_url"]
                    and known["credential_fingerprint"] == fingerprint):
                raise HTTPException(409, "这份 token 已绑定本机另一 Agent，请选择原实例重新导出")
        actor = broker.api_factory(session["center_url"], token=token).current_actor()
        if actor.get("actor_id") != session["actor"]["actor_id"]:
            raise HTTPException(403, "Agent token 必须属于当前个人身份")
        if "agent" not in actor.get("scopes", []) or set(actor.get("roles", [])) != {"member"}:
            raise HTTPException(403, "请使用管理员明确签发的受限 Agent token（agent scope）")
        storage._private_directory(root)
        store = PersonalCredentialStore(root / "credentials")
        existing = store.load()
        if existing and not secrets.compare_digest(existing["token"], token):
            raise HTTPException(409, "本机 Agent 登录已有不同凭据，请保留原记录")
        profile = profile or {"schema_version": 1, "agent_id": root.name,
            "actor_id": actor["actor_id"], "center_url": session["center_url"],
            "target": target, "label": label.strip(), "credential_fingerprint": fingerprint,
            "credential_id": actor.get("credential_id")}
        _write_json(path, profile)
        store.save(center_url=session["center_url"], token=token, actor=actor)
    else:
        if not profile:
            raise HTTPException(422, "新 Agent 需要独立签发的受限 token")
        store = PersonalCredentialStore(root / "credentials")
        existing = store.load()
        if not existing:
            raise HTTPException(401, "此 Agent 的本机登录已移除，需要原独立凭据或新建实例")
        if (existing.get("center_url") != session["center_url"]
                or hashlib.sha256(existing["token"].encode("utf-8")).hexdigest() != profile["credential_fingerprint"]):
            raise HTTPException(409, "此 Agent 的本机凭据与原始绑定不一致")
        actor = broker.api_factory(session["center_url"], token=existing["token"]).current_actor()
        if (actor.get("actor_id") != session["actor"]["actor_id"]
                or "agent" not in actor.get("scopes", []) or set(actor.get("roles", [])) != {"member"}):
            raise HTTPException(403, "此 Agent 的受限凭据或个人身份已失效")
    if profile.get("credential_id") and actor.get("credential_id") != profile["credential_id"]:
        raise HTTPException(409, "中心返回的 Agent 凭据标识已改变")
    agent_session = {**session, "actor": actor}
    return SimpleNamespace(root=root, session=lambda: agent_session), profile


def export_member_agent_config(broker, target: str, agent_id, *, label=None, token=None) -> dict:
    """Recheck the personal identity, then wrap the existing CLI artifacts.

    The caller cannot select a server path. The temporary files contain only
    public instructions and are removed after preparing the download.
    """
    if target not in AGENT_TARGETS:
        raise HTTPException(422, "unsupported_agent_target")
    with broker.lock:
        generation = broker.auth_generation
    session = broker.session(refresh=True)
    if not session.get("connected") or not session.get("actor", {}).get("actor_id"):
        raise HTTPException(401, "请先连接并核验个人身份")
    if not session.get("online") or not session.get("remote_actions_available"):
        reason = (session.get("connection_error") or {}).get("reason_code")
        raise HTTPException(401 if reason == "center_login_required" else 503,
                            "中心连接未确认，请先重新自检个人身份")
    actor_id = session["actor"]["actor_id"]
    label, entry = AGENT_TARGETS[target]
    with broker.lock:
        if (generation != broker.auth_generation or not broker.login or not broker.actor
                or broker.actor.get("actor_id") != actor_id
                or broker.login["center_url"] != session["center_url"]):
            raise HTTPException(409, "个人身份已改变，请重新自检后生成配置")
        from .agent_access import instruction_artifacts

        agent, profile = _agent_view(broker, session, target, agent_id, label, token)
        with TemporaryDirectory(prefix=".agent-export-", dir=broker.root) as temporary:
            artifacts = instruction_artifacts(agent, Path(temporary) / "instructions")
            documents = {
                "rcn-agent-access.json": Path(artifacts["config"]).read_text(encoding="utf-8"),
                "AGENT_ACCESS.md": Path(artifacts["instructions"]).read_text(encoding="utf-8"),
            }
        # Keep the established DPAPI consumer and immutable-runtime command.
        config = json.loads(documents["rcn-agent-access.json"])
        prefix = config.get("command_prefix")
        if (config.get("credential_storage") != "windows-current-user-dpapi"
                or config.get("token_argv_supported") is not False
                or not isinstance(prefix, list) or len(prefix) < 2 or prefix[1] != "-B"):
            raise HTTPException(500, "Agent 配置未通过本机安全合同")
        # The installed GUI broker runs under pythonw. Agents need the console
        # sibling so their subprocess can actually receive the JSON replies.
        if Path(prefix[0]).name.lower() == "pythonw.exe":
            console = Path(prefix[0]).with_name("python.exe")
            if not console.is_file():
                raise HTTPException(500, "找不到已安装客户端的命令行解释器")
            prefix[0] = str(console)
            documents["rcn-agent-access.json"] = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
        if generation != broker.auth_generation:
            raise HTTPException(409, "个人身份已改变，请重新自检后生成配置")
        guide = (f"# {label} 接入 RCN\n\n"
                 "将本压缩包中的三个文件放入需要使用 RCN 的项目目录。\n"
                 f"在该项目现有的 {entry} 中加入下面一行；不要覆盖原有项目规则：\n\n"
                 "请先阅读 ./AGENT_ACCESS.md，并使用 ./rcn-agent-access.json 中的 command_prefix 调用 RCN。\n\n"
                 "运行 status 与 capabilities 核对本人身份、联网状态、Profile 和额度。\n"
                 f"此 Agent 的独立实例编号：{profile['agent_id']}；名称：{profile['label']}。\n"
                 "配置引用此 Agent 专属目录的 CurrentUser DPAPI 登录，不含个人 token。\n"
                 "请在这台电脑的当前 Windows 用户下使用；复制到另一台电脑后应重新生成。\n"
                 "移除此 Agent 的本机登录不撤销中心 token；管理员可按原签发记录单独撤销该 token。\n")
        documents[f"{target.upper()}_SETUP.md"] = guide
        archive = BytesIO()
        with ZipFile(archive, "w", compression=ZIP_DEFLATED) as bundle:
            for filename, content in documents.items():
                bundle.writestr(filename, content.encode("utf-8"))
    return {"schema_version": 1, "target": target, "actor_id": actor_id,
            "agent_id": profile["agent_id"], "agent_label": profile["label"],
            "independent_credential": True,
            "center_url": session["center_url"], "identity_verified": True,
            "credential_included": False, "filename": f"RCN-Agent-{target}.zip",
            "media_type": "application/zip", "files": list(documents),
            "content_base64": base64.b64encode(archive.getvalue()).decode("ascii"),
            "setup_instructions": guide}
