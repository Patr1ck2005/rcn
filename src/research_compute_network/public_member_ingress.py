"""Narrow member ingress on the existing API, selected by the Tunnel's fixed Host.

The connector always overrides the origin Host. Public callers never select the
private management surface by supplying their own Host or forwarding headers.
"""
from __future__ import annotations

import html
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from fastapi.responses import HTMLResponse, PlainTextResponse
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route, Router

INGRESS_HOST = "rcn-member-ingress.local"
DEFAULT_PUBLIC_URL = "https://rcn.example.invalid"
PUBLIC_REPOSITORY = "https://github.com/Patr1ck2005/rcn"
_ID = r"[A-Za-z0-9_.-]{1,160}"
_PUBLIC = (
    (frozenset({"GET", "HEAD"}), re.compile(r"^/(?:join|agent-start)?$")),
    (frozenset({"GET"}), re.compile(r"^/v1/member-pairing-info$")),
    (frozenset({"GET"}), re.compile(r"^/v1/help/public(?:/[a-z0-9_-]+)?$")),
    (frozenset({"PUT", "GET"}), re.compile(r"^/v1/member-pairings/" + _ID + r"$")),
)
_AUTHENTICATED = (
    ({"GET"}, r"^/(?:health|v1/(?:me|profiles|projects|project-registrations|origin-adapters|origin-transfer|execution-runtime))$"),
    ({"GET"}, r"^/v1/me/(?:submission-policy|compute-credits|credits|enrollments)$"),
    ({"GET"}, r"^/v1/(?:overview|settings/features|operations/(?:summary|metrics|insights)|events)$"),
    ({"GET"}, r"^/v1/member-release$"),
    ({"GET"}, r"^/v1/machines/" + _ID + r"(?:/policy-revision)?$"),
    ({"PUT"}, r"^/v1/machines/" + _ID + r"/policy$"),
    ({"GET"}, r"^/v1/metadata-operations/" + _ID + r"$"),
    ({"GET"}, r"^/v1/help/(?:catalog|protected(?:/[a-z0-9_-]+)?)$"),
    ({"GET"}, r"^/v1/me/agent-credentials$"),
    ({"GET", "PUT", "DELETE"}, r"^/v1/me/agent-credentials/" + _ID + r"$"),
    ({"POST"}, r"^/v1/project-registrations$"),
    ({"PUT", "GET"}, r"^/v1/submission-operations/" + _ID + r"$"),
    ({"POST"}, r"^/v1/submission-operations/" + _ID + r"/confirm$"),
    ({"POST"}, r"^/v1/dispatcher/ensure-running$"),
    ({"GET"}, r"^/v1/jobs(?:/" + _ID + r"(?:/(?:contract|placement-diagnostics|artifact-manifests|origin-import-receipt|events|attempts))?)?$"),
    ({"POST"}, r"^/v1/jobs/" + _ID + r"/(?:cancel|retry|origin-import-receipt)$"),
    ({"GET", "PUT"}, r"^/v1/jobs/" + _ID + r"/origin-(?:assets|bundles)/" + _ID + r"$"),
    ({"POST"}, r"^/v1/jobs/" + _ID + r"/origin-upload-sessions$"),
    ({"GET", "DELETE"}, r"^/v1/jobs/" + _ID + r"/origin-upload-sessions/" + _ID + r"$"),
    ({"PUT"}, r"^/v1/jobs/" + _ID + r"/origin-upload-sessions/" + _ID + r"/chunk$"),
    ({"POST"}, r"^/v1/jobs/" + _ID + r"/origin-upload-sessions/" + _ID + r"/finalize$"),
    ({"GET"}, r"^/v1/jobs/" + _ID + r"/origin-results(?:/" + _ID + r"/" + _ID + r")?$"),
    ({"POST"}, r"^/v1/jobs/" + _ID + r"/origin-result-preparations$"),
    ({"GET", "DELETE"}, r"^/v1/jobs/" + _ID + r"/origin-result-preparations/" + _ID + r"$"),
    ({"GET"}, r"^/v1/jobs/" + _ID + r"/origin-result-preparations/" + _ID + r"/content$"),
)
_AUTHENTICATED = tuple((frozenset(methods), re.compile(pattern)) for methods, pattern in _AUTHENTICATED)


def member_ingress_settings(state_root: Path) -> dict:
    """Read one small deployment-owned public descriptor; fail closed on damage."""
    path = Path(state_root) / "member-ingress.json"
    defaults = {"enabled": False, "public_url": DEFAULT_PUBLIC_URL, "group_name": "课题组计算中心"}
    if not path.exists():
        return defaults
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        if set(value) - {"schema_version", "enabled", "public_url", "group_name"}:
            return defaults
        if value.get("schema_version") != 1 or type(value.get("enabled")) is not bool:
            return defaults
        url = urlsplit(value["public_url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}:
            return defaults
        group = value["group_name"]
        if not isinstance(group, str) or not 1 <= len(group) <= 100 or any(ord(c) < 32 for c in group):
            return defaults
        return {"enabled": value["enabled"], "public_url": value["public_url"].rstrip("/"), "group_name": group}
    except (OSError, ValueError, KeyError, TypeError):
        return defaults


def public_route_access(method: str, path: str) -> str | None:
    if "\\" in path or "%" in path or "//" in path or any(p in {".", ".."} for p in path.split("/")):
        return None
    for methods, pattern in _PUBLIC:
        if method in methods and pattern.fullmatch(path):
            return "public"
    for methods, pattern in _AUTHENTICATED:
        if method in methods and pattern.fullmatch(path):
            return "authenticated"
    return None


class PublicMemberIngress:
    def __init__(self, app, *, state_root: Path):
        self.app = app
        self.settings = member_ingress_settings(state_root)
        self.pages = build_public_member_pages(state_root)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        host = headers.get(b"host", b"").decode("latin-1").lower().split(":", 1)[0]
        actual_host = urlsplit(self.settings["public_url"]).hostname
        if host not in {INGRESS_HOST, actual_host}:
            return await self.app(scope, receive, send)

        async def private_response(message):
            if message["type"] == "http.response.start":
                response_headers = [(k, v) for k, v in message.get("headers", [])
                                    if k.lower() not in {b"cache-control", b"pragma"}]
                response_headers.extend([(b"cache-control", b"no-store, private"), (b"pragma", b"no-cache"),
                                         (b"x-content-type-options", b"nosniff")])
                message = {**message, "headers": response_headers}
            await send(message)

        # The connector reaches loopback HTTP for both edge schemes. Cloudflare
        # supplies the original scheme; do not change other sites' zone policy.
        if headers.get(b"x-forwarded-proto", b"").lower() == b"http":
            destination = self.settings["public_url"] + scope.get("path", "/")
            query = scope.get("query_string", b"").decode("latin-1")
            if query:
                destination += "?" + query
            return await RedirectResponse(destination, status_code=308)(scope, receive, private_response)

        async def reject(code, reason):
            await JSONResponse({"detail": {"reason_code": reason}}, status_code=code)(scope, receive, private_response)

        if not self.settings["enabled"]:
            return await reject(503, "public_member_ingress_unavailable")
        access = public_route_access(scope["method"], scope["path"])
        if access is None:
            return await reject(404, "member_route_not_available")
        # Do not inherit local-pilot trust simply because cloudflared is loopback.
        if access == "authenticated" and not headers.get(b"authorization", b"").startswith(b"Bearer "):
            return await reject(401, "personal_login_required")
        if scope["path"] in {"/", "/join", "/agent-start"}:
            return await self.pages(scope, receive, private_response)
        if scope["path"].startswith("/v1/member-pairings/") and scope["method"] == "PUT":
            try:
                length = int(headers.get(b"content-length", b"0"))
            except ValueError:
                return await reject(400, "invalid_pairing_request")
            if length > 16384:
                return await reject(413, "pairing_request_too_large")
            size = 0
            class BodyLimit(Exception):
                pass
            async def bounded_receive():
                nonlocal size
                message = await receive()
                size += len(message.get("body", b""))
                if size > 16384:
                    raise BodyLimit()
                return message
            try:
                return await self.app(scope, bounded_receive, private_response)
            except BodyLimit:
                return await reject(413, "pairing_request_too_large")
        return await self.app(scope, receive, private_response)


def build_public_member_pages(state_root: Path):
    async def agent_start(_request):
        settings = member_ingress_settings(state_root)
        return PlainTextResponse("\n".join([
            "# RCN 成员 Agent 开始", "",
            f"课题组：{settings['group_name']}", f"中心：{settings['public_url']}",
            f"软件下载和 SHA-256：{PUBLIC_REPOSITORY}/releases", "",
            "1. 读取发行说明，下载通用 RCN-Member-Setup.exe 并核对 SHA-256，以当前 Windows 用户安装。",
            "2. 使用安装后的稳定入口。未安装时不要克隆源码、创建中心或索取 SSH 密钥。",
            "```powershell", "$rcn = Join-Path $env:LOCALAPPDATA 'ResearchComputeNetwork/member-client/bin/RCN-Agent.exe'",
            f"& $rcn join --center '{settings['public_url']}' --name '<成员姓名>' --agent codex --wait 120", "```",
            "将姓名和 Agent 类型替换为本人实际值（codex/claude/dsh/generic）。",
            "3. 展示配对码，由管理员核对并批准一次；等待结束后使用 join --status 继续原申请。",
            "4. 成功后使用返回的专属 command_prefix，读取 help list、context 和 doctor。",
            "5. 任务准备依照所属项目合同和 help read member-task-package；缺项先指出，不猜科学参数。", "",
            "保留原配对、Job 和下载操作编号。不要创建第二次提交来处理回复丢失。",
            "安装连接不自动开启机器贡献；已有暂停保持。系统安装确认由本人处理。", "",
        ]))

    async def join_page(_request):
        settings = member_ingress_settings(state_root)
        name = html.escape(settings["group_name"])
        center = html.escape(settings["public_url"])
        return HTMLResponse(f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>加入 {name}</title>
<style>body{{font:17px/1.75 system-ui,sans-serif;background:#f4f8f6;color:#18362a;margin:0}}main{{max-width:760px;margin:10vh auto;padding:32px}}h1{{font-size:2.25rem;line-height:1.3}}a{{color:#08764e}}.box{{background:white;border:1px solid #d4e2db;border-radius:14px;padding:24px;margin:24px 0}}code{{overflow-wrap:anywhere}}li{{margin:12px 0}}</style>
<main><p>Research Compute Network</p><h1>加入 {name}</h1><p>安装一次，管理员确认一次，之后由你的 Agent 接续科研任务。</p>
<div class="box"><ol><li><a href="{PUBLIC_REPOSITORY}/releases">下载安装包</a>，以自己的 Windows 用户安装。</li>
<li>在客户端选择“加入课题组”，中心填写 <code>{center}</code>，填写姓名并提交申请。</li>
<li>让管理员核对配对码并批准。客户端将自动连接、配置 Agent 并自检。</li></ol></div>
<p><a href="/agent-start">把这份开始说明交给你的 Agent</a> · <a href="{PUBLIC_REPOSITORY}/blob/main/docs/member-onboarding-guide.md">完整成员指南</a></p>
<p>无需个人接入包或 SSH 配置。仅提交任务无需贡献电脑，也无需在本机安装 COMSOL。</p></main></html>""")
    return Router(routes=[Route("/", join_page), Route("/join", join_page), Route("/agent-start", agent_start)])
