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
    target: Literal["codex", "claude", "dsh", "generic"]
    agent_id: UUID
    label: str | None = None
    token: SecretStr | None = None


AGENT_TARGETS = {
    "codex": ("Codex", "AGENTS.md"),
    "claude": ("Claude Code", "CLAUDE.md"),
    "dsh": ("DSH", "AGENTS.md"),
    "generic": ("Agent", "项目说明文件"),
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


def member_connection_root(broker):
    """Reuse the parent transport only for this exact isolated Agent login.

    The command keeps its own DPAPI credentials and journals. Resolve the
    parent's pinned transport afresh; never copy keys or cache its validation.
    """
    root = broker.root
    path = root / "agent-profile.json"
    if not path.exists() or not broker.login:
        return root
    storage._check_private_file(path)
    profile = _read_profile(path)
    actor = (broker.login.get("actor") or {}).get("actor_id")
    fingerprint = hashlib.sha256(broker.login["token"].encode("utf-8")).hexdigest()
    if (root.parent.name != "agents" or profile["agent_id"] != root.name
            or profile.get("registration_state", "confirmed") != "confirmed"
            or profile.get("actor_id") != actor
            or profile.get("center_url") != broker.login.get("center_url")
            or not secrets.compare_digest(profile["credential_fingerprint"], fingerprint)):
        raise PermissionError("member_agent_connection_binding_changed")
    return root.parent.parent


def _present_profile(profile, root):
    return {key: profile[key] for key in ("agent_id", "actor_id", "center_url", "target", "label")} | {
        "credential_id": profile.get("credential_id"),
        "registration_state": profile.get("registration_state", "confirmed"),
        "self_service": profile.get("credential_origin") == "self_service",
        "configured": (profile.get("registration_state", "confirmed") == "confirmed"
                       and (root / "credentials" / "personal-login.dpapi").is_file())}


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
            "next_action": ("如需关闭中心访问，请在成员端单独撤销此 Agent。"
                if profile.get("credential_origin") == "self_service" else
                "如需撤销中心凭据，请让管理员按原签发记录单独撤销此 Agent token。")}


def _legacy_agent_view(broker, session, target, agent_id, label, token):
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
        actor = broker._api(session["center_url"], token=token).current_actor()
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
        actor = broker._api(session["center_url"], token=existing["token"]).current_actor()
        if (actor.get("actor_id") != session["actor"]["actor_id"]
                or "agent" not in actor.get("scopes", []) or set(actor.get("roles", [])) != {"member"}):
            raise HTTPException(403, "此 Agent 的受限凭据或个人身份已失效")
    if profile.get("credential_id") and actor.get("credential_id") != profile["credential_id"]:
        raise HTTPException(409, "中心返回的 Agent 凭据标识已改变")
    agent_session = {**session, "actor": actor}
    agent_login = {"center_url": session["center_url"], "actor": actor,
                   "token": token if token is not None else existing["token"]}
    return SimpleNamespace(root=root, session=lambda: agent_session, login=agent_login), profile


def _agent_view(broker, session, target, agent_id, label, token):
    """Register a generated credential, retaining pre-issued-token compatibility.

    The DPAPI envelope also carries the original binding, so a crash between
    saving it and publishing the public journal cannot rotate the credential.
    Pending credentials are unusable by member_connection_root until /v1/me
    confirms the exact server credential ID, person, scopes and roles.
    """
    from .member_client import _write_json
    path = _profile_path(broker, agent_id)
    prior = _read_profile(path) if path.exists() else None
    if token is not None and prior and prior.get("credential_origin") == "self_service":
        raise HTTPException(422, "此 Agent 的凭据由客户端自动管理，无需填写 token")
    if token is not None or (prior and prior.get("credential_origin") != "self_service"):
        return _legacy_agent_view(broker, session, target, agent_id, label, token)
    if "agent" in session["actor"].get("scopes", []):
        raise HTTPException(403, "请使用个人登录创建 Agent")
    root = path.parent
    storage._private_directory(root)
    with storage._exclusive(root):
        profile = _read_profile(path) if path.exists() else None
        store = PersonalCredentialStore(root / "credentials")
        existing = store.load()
        if profile is None and existing:
            profile = (existing.get("actor") or {}).get("agent_registration")
            if not isinstance(profile, dict):
                raise HTTPException(409, "此 Agent 目录存在未识别的本机凭据，请保留原记录")
        if profile:
            if (profile["agent_id"] != str(UUID(str(agent_id)))
                    or profile["actor_id"] != session["actor"]["actor_id"]
                    or profile["center_url"] != session["center_url"] or profile["target"] != target):
                raise HTTPException(403, "本机 Agent 配置与当前身份不一致")
            if label is not None and label.strip() != profile["label"]:
                raise HTTPException(409, "请沿用此 Agent 的原始名称")
            if profile.get("registration_state") == "revoked":
                raise HTTPException(401, "此 Agent 已撤销；请新建实例")
            if not existing:
                raise HTTPException(401, "此 Agent 的本机登录已移除；请新建实例")
            secret = existing["token"]
            original = (existing.get("actor") or {}).get("agent_registration")
            immutable = ("agent_id", "actor_id", "center_url", "target", "label", "credential_fingerprint")
            if (not isinstance(original, dict)
                    or any(original.get(key) != profile.get(key) for key in immutable)):
                raise HTTPException(409, "此 Agent 的原始加密绑定与本机记录不一致")
            if (existing.get("center_url") != profile["center_url"]
                    or hashlib.sha256(secret.encode("utf-8")).hexdigest() != profile["credential_fingerprint"]):
                raise HTTPException(409, "此 Agent 的本机凭据与原始绑定不一致")
        else:
            if (not isinstance(label, str) or not 1 <= len(label.strip()) <= 80
                    or any(ord(c) < 32 or ord(c) == 127 for c in label)):
                raise HTTPException(422, "请填写不超过 80 字符的 Agent 名称")
            secret = secrets.token_urlsafe(32)
            profile = {"schema_version": 1, "agent_id": root.name,
                "actor_id": session["actor"]["actor_id"], "center_url": session["center_url"],
                "target": target, "label": label.strip(),
                "credential_fingerprint": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
                "credential_id": None, "credential_origin": "self_service", "registration_state": "pending"}
            # No network call can precede this encrypted durable save. A DPAPI
            # failure leaves the center untouched and never uses plaintext.
            store.save(center_url=session["center_url"], token=secret,
                       actor={"actor_id": profile["actor_id"], "agent_registration": profile})
        _write_json(path, profile)
        generation = broker.auth_generation
        personal_token = broker.login["token"]
        response = broker._api(session["center_url"], token=personal_token)._request("PUT",
            f"/v1/me/agent-credentials/{profile['agent_id']}",
            {"label": profile["label"], "target": profile["target"],
             "token_hash": profile["credential_fingerprint"]})
        if (generation != broker.auth_generation or not broker.login
                or broker.login["token"] != personal_token
                or broker.login["center_url"] != profile["center_url"]):
            raise HTTPException(409, "个人身份已改变，请重新自检后生成配置")
        if (not isinstance(response, dict) or response.get("agent_id") != profile["agent_id"]
                or response.get("owner_id") != profile["actor_id"]
                or response.get("label") != profile["label"] or response.get("target") != profile["target"]
                or not response.get("credential_id")
                or profile.get("credential_id") not in {None, response["credential_id"]}):
            raise HTTPException(409, "中心返回的 Agent 原始绑定不一致")
        if response.get("state") != "active" or response.get("active") is not True:
            profile = {**profile, "credential_id": response["credential_id"], "registration_state": "revoked"}
            _write_json(path, profile)
            raise HTTPException(401, "此 Agent 的中心凭据已失效；请新建实例")
        actor = broker._api(session["center_url"], token=secret).current_actor()
        if (actor.get("actor_id") != profile["actor_id"]
                or actor.get("credential_id") != response["credential_id"]
                or set(actor.get("scopes", [])) != {"api", "agent"}
                or set(actor.get("roles", [])) != {"member"}):
            raise HTTPException(403, "中心未确认此 Agent 的独立受限身份")
        if generation != broker.auth_generation:
            raise HTTPException(409, "个人身份已改变，请重新自检后生成配置")
        profile = {**profile, "credential_id": response["credential_id"], "registration_state": "confirmed"}
        store.save(center_url=session["center_url"], token=secret,
                   actor={**actor, "agent_registration": profile})
        _write_json(path, profile)
    return SimpleNamespace(root=root, session=lambda: {**session, "actor": actor},
        login={"center_url": session["center_url"], "token": secret, "actor": actor}), profile


def _verified_personal_session(broker):
    generation = broker.auth_generation
    session = broker.session(refresh=True)
    if not session.get("connected") or not session.get("actor", {}).get("actor_id"):
        raise HTTPException(401, "请先连接并核验个人身份")
    if not session.get("online") or not session.get("remote_actions_available"):
        reason = (session.get("connection_error") or {}).get("reason_code")
        raise HTTPException(401 if reason == "center_login_required" else 503,
                            "中心连接未确认，请先重新自检个人身份")
    if (generation != broker.auth_generation or not broker.login or not broker.actor
            or broker.actor.get("actor_id") != session["actor"]["actor_id"]
            or broker.login["center_url"] != session["center_url"]):
        raise HTTPException(409, "个人身份已改变，请重新自检后生成配置")
    return generation, session


def configure_member_agent(broker, target, agent_id, *, label=None):
    """Create/reconcile an automatic credential without exporting a bundle."""
    if target not in AGENT_TARGETS:
        raise HTTPException(422, "unsupported_agent_target")
    with broker.lock:
        _, session = _verified_personal_session(broker)
        agent, profile = _agent_view(broker, session, target, agent_id, label, None)
        return _present_profile(profile, agent.root)


def revoke_member_agent_credential(broker, agent_id):
    """Idempotently revoke this center binding, then remove its local login."""
    from .member_client import _write_json
    with broker.lock:
        generation, session = _verified_personal_session(broker)
        path = _profile_path(broker, agent_id)
        if not path.exists():
            raise HTTPException(404, "本机 Agent 配置不存在")
        profile = _read_profile(path)
        if (profile["actor_id"] != session["actor"]["actor_id"]
                or profile["center_url"] != session["center_url"]):
            raise HTTPException(403, "本机 Agent 配置属于另一位成员")
        if profile.get("credential_origin") != "self_service":
            raise HTTPException(409, "旧预签发凭据仍须按原签发记录撤销")
        response = broker._api(session["center_url"], token=broker.login["token"])._request(
            "DELETE", f"/v1/me/agent-credentials/{profile['agent_id']}")
        if (generation != broker.auth_generation or response.get("agent_id") != profile["agent_id"]
                or response.get("owner_id") != profile["actor_id"] or response.get("state") != "revoked"
                or response.get("active") is not False
                or (profile.get("credential_id") and response.get("credential_id") != profile["credential_id"])):
            raise HTTPException(409, "中心未确认此 Agent 的撤销状态")
        profile = {**profile, "registration_state": "revoked", "credential_id": response["credential_id"]}
        _write_json(path, profile)
        store = PersonalCredentialStore(path.parent / "credentials")
        if store.path.exists():
            store.clear()
        return {**_present_profile(profile, path.parent), "center_token_revoked": True,
                "local_login_removed": True}


def revoke_member_agent(broker, agent_id):
    """Local-route compatibility name for the explicit center revocation."""
    return revoke_member_agent_credential(broker, agent_id)


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
    target_label, entry = AGENT_TARGETS[target]
    with broker.lock:
        if (generation != broker.auth_generation or not broker.login or not broker.actor
                or broker.actor.get("actor_id") != actor_id
                or broker.login["center_url"] != session["center_url"]):
            raise HTTPException(409, "个人身份已改变，请重新自检后生成配置")
        from .agent_access import instruction_artifacts

        agent, profile = _agent_view(broker, session, target, agent_id, label, token)
        with TemporaryDirectory(prefix=".agent-export-", dir=broker.root) as temporary:
            directory = Path(temporary) / "instructions"
            artifacts = instruction_artifacts(agent, directory)
            documents = {
                "rcn-agent-access.json": Path(artifacts["config"]).read_text(encoding="utf-8"),
                "AGENT_ACCESS.md": Path(artifacts["instructions"]).read_text(encoding="utf-8"),
            }
            # The installed command may add version-matched offline help.
            # Only Markdown under this temporary instruction root is exported.
            for article in sorted(directory.rglob("*.md")):
                storage._unlinked(article)
                name = article.relative_to(directory).as_posix()
                if name not in documents:
                    documents[name] = article.read_text(encoding="utf-8")
        # Keep the established DPAPI consumer and immutable-runtime command.
        config = json.loads(documents["rcn-agent-access.json"])
        prefix = config.get("command_prefix")
        stable_launcher = config.get("launcher_kind") == "active-installed-version"
        prefix_valid = (isinstance(prefix, list) and all(isinstance(part, str) for part in prefix)
            and ((stable_launcher and len(prefix) == 3 and Path(prefix[0]).name == "RCN-Agent.exe"
                  and prefix[1:] == ["--state-root", str(agent.root)])
                 or (not stable_launcher and len(prefix) == 6 and prefix[1:5] == [
                     "-B", "-m", "research_compute_network.agent_access", "--state-root"]
                     and prefix[5] == str(agent.root))))
        if (config.get("credential_storage") != "windows-current-user-dpapi"
                or config.get("token_argv_supported") is not False or not prefix_valid
                or not Path(prefix[0]).is_absolute() or not Path(prefix[0]).is_file()):
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
        guide = (f"# {target_label} 接入 RCN\n\n"
                 "这段说明可以直接交给本机 Agent；无需先找到源码仓库或下载配置。\n"
                 "当前 Agent 的命令前缀（JSON 参数数组，不含秘密）：\n\n```json\n"
                 + json.dumps(prefix, ensure_ascii=False) + "\n```\n\n"
                 "在该前缀后依次追加 `help list --format json`、`help read member-getting-started`、"
                 "`help read member-task-package`、`context` 和 `doctor`。按数组参数执行，不把整段 JSON 当成一条 shell 命令。\n"
                 "先读取当前项目已有规则与科学合同，缺少扫描、输出或耗时信息时明确指出缺项。\n"
                 "需要文件化配置时，下载 ZIP 并将其中的文件放入需要使用 RCN 的项目目录。\n"
                 f"在该项目现有的 {entry} 中加入下面一行；不要覆盖原有项目规则：\n\n"
                 "请先阅读 ./AGENT_ACCESS.md，并使用 ./rcn-agent-access.json 中的 command_prefix 调用 RCN。\n\n"
                 "先运行 help list、context 和 doctor，再用 status 与 capabilities 核对本人身份、Profile 和额度。\n"
                 f"此 Agent 的独立实例编号：{profile['agent_id']}；名称：{profile['label']}。\n"
                 "配置引用此 Agent 专属目录的 CurrentUser DPAPI 登录，不含个人 token。\n"
                 "请在这台电脑的当前 Windows 用户下使用；复制到另一台电脑后应重新生成。\n"
                 "移除此 Agent 的本机登录不撤销中心凭据；在成员端撤销此 Agent 可单独关闭其中心访问。\n")
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
