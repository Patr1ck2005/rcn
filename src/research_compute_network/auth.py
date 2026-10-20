"""Bearer-token authentication backed by hashed token records."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from fastapi import Header, HTTPException, status

from .models import MachineAgentCredential, UserRole
from .repository import MetadataRepository


@dataclass(frozen=True)
class AuthContext:
    actor_id: str
    roles: frozenset[UserRole]
    scopes: frozenset[str]
    credential_id: str | None = None

    def has_role(self, role: UserRole) -> bool:
        return role in self.roles


class PilotAuthenticator:
    def __init__(self, repository: MetadataRepository, *, allow_local_trusted: bool = True) -> None:
        self.repository = repository
        self.allow_local_trusted = allow_local_trusted

    def actor(self, authorization: str | None = Header(default=None)) -> AuthContext:
        if not authorization:
            if self.allow_local_trusted:
                return AuthContext(
                    actor_id="local-pilot",
                    roles=frozenset({UserRole.ADMIN, UserRole.MEMBER, UserRole.MACHINE_OWNER}),
                    scopes=frozenset({"api"}),
                )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid authorization scheme")
        secret = authorization.removeprefix("Bearer ").strip()
        token_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        token = self.repository.get_token_by_hash(token_hash)
        if token is None or not token.is_active():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bearer token")
        user = self.repository.get_user(token.user_id)
        if user is None or not user.active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="inactive token owner")
        return AuthContext(
            actor_id=user.user_id,
            # Agent credentials keep the person's identity and submission
            # policy, but cannot inherit present or future administrator roles.
            roles=frozenset({UserRole.MEMBER}) if "agent" in token.scopes else frozenset(user.roles),
            scopes=frozenset(token.scopes),
            credential_id=token.token_id,
        )

    def machine_agent(
        self,
        machine_id: str,
        authorization: str | None,
    ) -> MachineAgentCredential:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing machine agent token")
        secret = authorization.removeprefix("Bearer ").strip()
        token_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        credential = self.repository.get_machine_credential_by_hash(token_hash)
        if credential is None or not credential.is_active():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid machine agent token")
        if credential.machine_id != machine_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="machine agent token is bound to another machine")
        return credential


def require_role(context: AuthContext, *roles: UserRole) -> None:
    if UserRole.ADMIN in context.roles or any(role in context.roles for role in roles):
        return
    required = roles[0] if roles else UserRole.MEMBER
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "reason_code": "role_required",
            "message": "该功能存在，但当前身份缺少所需角色。",
            "missing_roles": [role.value for role in roles],
            "current_state": "role_not_granted",
            "next_action": "在项目页面查看申请路径，或联系管理员授予所需角色",
            "action_path": "/app/projects",
            "requires": required.value,
        },
    )
