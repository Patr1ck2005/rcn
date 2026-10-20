"""Remote-root layout and deletion safety rules.

The control plane never accepts a task-provided absolute directory.  An
administrator chooses one machine root and all job paths are derived below it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PureWindowsPath


ROOT_MARKER = ".rcn-root.json"
RUN_MARKER = ".rcn-run.json"
DEFAULT_REMOTE_ROOT = r"D:\ResearchComputeNetwork"

_FORBIDDEN_PARTS = {
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
    "comsol",
    "comsol64",
    "comsol_worker",
}


def validate_remote_root_path(path: str) -> PureWindowsPath:
    """Validate the administrator-selected root without touching the worker."""
    if not path or not re.match(r"^[A-Za-z]:\\", path):
        raise ValueError("remote root must be an absolute Windows path")
    root = PureWindowsPath(path)
    if len(root.parts) < 2 or str(root) == root.anchor:
        raise ValueError("drive roots cannot be used as compute roots")
    lowered = [part.casefold() for part in root.parts[1:]]
    if any(part in _FORBIDDEN_PARTS for part in lowered):
        raise ValueError("remote root overlaps a protected or legacy directory")
    if len(root.parts) == 2 and lowered[0] in {"users", "documents and settings"}:
        raise ValueError("user-home roots cannot be used as compute roots")
    if "users" in lowered:
        users_index = lowered.index("users")
        if len(lowered) <= users_index + 2:
            raise ValueError("a user profile or its immediate root cannot be used")
    return root


def safe_component(value: str, *, label: str) -> str:
    if not value or not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        raise ValueError(f"{label} contains unsafe path characters")
    if value in {".", ".."}:
        raise ValueError(f"{label} cannot be dot path")
    return value


@dataclass(frozen=True)
class RemoteLayout:
    root: PureWindowsPath

    @classmethod
    def from_string(cls, root: str) -> "RemoteLayout":
        return cls(validate_remote_root_path(root))

    @property
    def marker(self) -> PureWindowsPath:
        return self.root / ROOT_MARKER

    @property
    def agent(self) -> PureWindowsPath:
        return self.root / "agent"

    @property
    def incoming(self) -> PureWindowsPath:
        return self.root / "spool" / "incoming"

    @property
    def ready(self) -> PureWindowsPath:
        return self.root / "spool" / "ready"

    @property
    def cancel(self) -> PureWindowsPath:
        return self.root / "spool" / "cancel"

    @property
    def status(self) -> PureWindowsPath:
        return self.root / "spool" / "status"

    def active_run(self, project_id: str, job_id: str, unit_id: str) -> PureWindowsPath:
        return self.root / "runs" / "active" / safe_component(project_id, label="project_id") / safe_component(
            job_id, label="job_id"
        ) / safe_component(unit_id, label="work_unit_id")

    def retained_run(self, outcome: str, project_id: str, job_id: str, unit_id: str) -> PureWindowsPath:
        if outcome not in {"success", "failed"}:
            raise ValueError("retained outcome must be success or failed")
        return self.root / "runs" / "retained" / outcome / safe_component(
            project_id, label="project_id"
        ) / safe_component(job_id, label="job_id") / safe_component(unit_id, label="work_unit_id")

    def relative(self, path: PureWindowsPath) -> str:
        return str(path.relative_to(self.root)).replace("\\", "/")


def deletion_is_authorized(
    *,
    configured_root_uuid: str,
    root_marker_uuid: str,
    run_marker_uuid: str,
    candidate_relative_path: str,
) -> bool:
    """Pure guard used by both API and remote cleanup implementation."""
    normalized = candidate_relative_path.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part]
    return (
        bool(configured_root_uuid)
        and configured_root_uuid == root_marker_uuid == run_marker_uuid
        and len(parts) >= 6
        and parts[:2] == ["runs", "retained"]
        and parts[2] in {"success", "failed"}
        and ".." not in parts
    )

