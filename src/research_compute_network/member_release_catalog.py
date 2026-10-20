"""Operator-owned runtime catalogue for the public platform.

No scientific archives are shipped. RCN_RUNTIME_DESCRIPTOR must name a local,
explicit operator approval. Its archive is never downloaded or executed here;
machine consent, pinned transport, pause and execution approvals still apply.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .runtime_policy import UNCONFIGURED_RUNTIME_VERSION

BASE_RUNTIME = MEMBER_RUNTIME = UNCONFIGURED_RUNTIME_VERSION
BASE_ARCHIVE_SHA256 = MEMBER_ARCHIVE_SHA256 = MEMBER_SUPERVISOR_SHA256 = MEMBER_MANIFEST_SHA256 = ""


class RuntimeNotConfigured(ValueError):
    reason_code = "runtime_not_configured"

    def __init__(self):
        super().__init__(self.reason_code)


@dataclass(frozen=True)
class MemberRelease:
    runtime_version: str
    archive_sha256: str
    supervisor_sha256: str
    base_runtime_version: str = BASE_RUNTIME
    owner_session_required: bool = False
    external_archive_path: str | None = None
    actor_id: str = ""
    reason: str = ""

    @property
    def configured(self):
        return bool(self.external_archive_path)

    def require_configured(self):
        if not self.configured:
            raise RuntimeNotConfigured()
        return self

    @property
    def archive_path(self):
        self.require_configured()
        return Path(self.external_archive_path)


PUBLIC_RELEASE = MemberRelease(BASE_RUNTIME, "", "")


def _document(path):
    from .storage_roots import reject_reparse_path
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("runtime_descriptor_path_invalid")
    reject_reparse_path(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16384:
        raise ValueError("runtime_descriptor_bounds")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("runtime_descriptor_changed")
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError("runtime_descriptor_bounds")
    reject_reparse_path(path)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("runtime_descriptor_duplicate_field")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)


def selected_center_release():
    """Read the local operator approval; an API caller cannot mint one."""
    name = os.environ.get("RCN_RUNTIME_DESCRIPTOR", "").strip()
    if not name:
        if os.environ.get("RCN_MEMBER_RELEASE_RUNTIME", "").strip():
            raise RuntimeNotConfigured()
        return PUBLIC_RELEASE
    value = _document(Path(name))
    fields = {"format", "runtime_version", "archive_sha256", "supervisor_sha256",
              "archive_path", "actor_id", "reason", "owner_session_required"}
    if (not isinstance(value, dict) or set(value) != fields
            or value["format"] != "rcn-public-runtime-approval-v1"
            or value["owner_session_required"] is not True
            or any(not isinstance(value[key], str) or not value[key].strip()
                   for key in fields - {"owner_session_required"})):
        raise ValueError("runtime_descriptor_invalid")
    if (not re.fullmatch(r"[a-f0-9]{24}", value["runtime_version"])
            or value["runtime_version"] == BASE_RUNTIME
            or any(not re.fullmatch(r"[a-f0-9]{64}", value[key])
                   for key in ("archive_sha256", "supervisor_sha256"))):
        raise ValueError("runtime_descriptor_fingerprint_invalid")
    archive = Path(value["archive_path"])
    if not archive.is_absolute() or ".." in archive.parts:
        raise ValueError("runtime_archive_path_invalid")
    from .storage_roots import reject_reparse_path
    reject_reparse_path(archive)
    metadata = archive.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8*1024*1024:
        raise ValueError("runtime_archive_bounds")
    with archive.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("runtime_archive_changed")
        raw = stream.read(8*1024*1024 + 1)
    reject_reparse_path(archive)
    if len(raw) > 8*1024*1024 or hashlib.sha256(raw).hexdigest() != value["archive_sha256"]:
        raise ValueError("runtime_archive_integrity")
    selected = os.environ.get("RCN_MEMBER_RELEASE_RUNTIME", value["runtime_version"])
    if selected != value["runtime_version"]:
        raise ValueError("member_runtime_not_in_approved_catalog")
    release = MemberRelease(value["runtime_version"], value["archive_sha256"],
        value["supervisor_sha256"], base_runtime_version=value["runtime_version"],
        owner_session_required=True, external_archive_path=str(archive),
        actor_id=value["actor_id"], reason=value["reason"])
    from .member_runtime import validate_runtime_archive
    from .member_registration import MemberRegistrationError
    try:
        validate_runtime_archive(raw, release=release)
    except MemberRegistrationError as exc:
        raise ValueError("runtime_archive_invalid") from exc
    return release


def release_for_runtime(version):
    release = selected_center_release()
    if version != release.runtime_version:
        raise ValueError("member_runtime_not_in_approved_catalog")
    return release


def current_member_release():
    return selected_center_release()


def approved_release_descriptor(value):
    release = selected_center_release()
    if value is None:
        return release
    if isinstance(value, MemberRelease):
        if value != release:
            raise ValueError("member_release_descriptor_changed")
    elif (not isinstance(value, dict) or set(value) != {"runtime_version", "archive_sha256"}
          or value != {"runtime_version": release.runtime_version,
                       "archive_sha256": release.archive_sha256}):
        raise ValueError("member_release_descriptor_changed")
    return release


def approved_scientific_equivalence(release=None):
    # Runtime approval cannot assert scientific equivalence without origin evidence.
    raise ValueError("scientific_equivalence_not_configured")


def build_member_runtime(base_archive, gate_source):
    raise ValueError("operator_runtime_build_required")
