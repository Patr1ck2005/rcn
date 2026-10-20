"""Stable filesystem locations for installed control-plane services."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .storage_roots import StorageRootRegistry, load_storage_registry, assert_writes_enabled


RCN_HOME_ENV = "RCN_HOME"
RCN_DATABASE_URL_ENV = "RCN_DATABASE_URL"
LEGACY_DATABASE_URL_ENV = "RCN_PILOT_DATABASE_URL"


def default_rcn_home() -> Path:
    configured = os.environ.get(RCN_HOME_ENV)
    if configured:
        return Path(configured).expanduser().resolve()
    if os.name == "nt":
        return (Path(os.environ.get("LOCALAPPDATA", Path.home())) / "ResearchComputeNetwork" / "control-plane").resolve()
    return (Path.home() / ".local" / "share" / "research-compute-network" / "control-plane").resolve()


@dataclass(frozen=True)
class ControlPlanePaths:
    root: Path
    database: Path
    demo_database: Path
    backups: Path
    dispatcher_bundles: Path
    origin_spool: Path
    ssh: Path
    onboarding: Path
    releases: Path
    storage_registry: StorageRootRegistry

    @classmethod
    def from_root(cls, root: str | Path | None = None) -> "ControlPlanePaths":
        resolved = Path(root).expanduser().resolve() if root is not None else default_rcn_home()
        registry = load_storage_registry(resolved)
        return cls(
            root=resolved,
            database=resolved / "control-plane.db",
            demo_database=resolved / "demo-control-plane.db",
            backups=resolved / "backups",
            dispatcher_bundles=registry.path_for("dispatcher_bundles", resolved / "dispatcher" / "bundles"),
            origin_spool=registry.path_for("origin_spool", resolved / "origin-spool"),
            ssh=resolved / "ssh",
            onboarding=resolved / "onboarding",
            releases=resolved / "releases",
            storage_registry=registry,
        )

    @property
    def storage_config(self) -> Path:
        return self.storage_registry.config_path

    @property
    def storage_ledger(self) -> Path:
        """Capacity and lifecycle tables share the original metadata authority."""
        return self.database

    def validate_storage(self, role: str) -> Path:
        """Strict role guard, intended as a callback at each data IO boundary."""
        default = self.root / ("origin-spool" if role == "origin_spool" else "dispatcher/bundles")
        return self.storage_registry.validate(role, default)

    def validate_storage_write(self, role: str) -> Path:
        assert_writes_enabled(self.root, role)
        return self.validate_storage(role)

    def ensure(self) -> "ControlPlanePaths":
        self.root.mkdir(parents=True, exist_ok=True)
        return self


def database_url(explicit: str | None = None, *, demo: bool = False) -> str:
    if explicit:
        return explicit
    configured = os.environ.get(RCN_DATABASE_URL_ENV) or os.environ.get(LEGACY_DATABASE_URL_ENV)
    if configured:
        return configured
    paths = ControlPlanePaths.from_root().ensure()
    database = paths.demo_database if demo else paths.database
    return f"sqlite:///{database.as_posix()}"
