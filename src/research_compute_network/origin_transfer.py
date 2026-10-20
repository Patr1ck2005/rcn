"""Bounded, immutable byte handoff; scientific ownership remains at origin."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path, PurePosixPath
from pydantic import BaseModel, Field

from .models import FileRecord, WorkUnit


class OriginTransferJobView(BaseModel):
    """Internal read-only binding view, not a Job submission/persistence model.

    A selected WorkUnit retains its actual ordinal and payload. Global partition
    coverage was validated on submission; this view never rewrites that contract.
    """
    job_id: str
    origin_submitter_id: str
    project_id: str
    user_id: str
    execution_profile_id: str
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    template_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    input_manifest: list[FileRecord]
    work_units: list[WorkUnit]

from .hashing import sha256_file


TRANSFER_PROTOCOL = 1
CHUNK_BYTES = 1024 * 1024
_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", re.I)


def portable_parts(value: str) -> tuple[str, ...]:
    """Reject Windows aliases/ADS as well as traversal, even on POSIX tests."""
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("invalid managed relative path")
    parts = value.split("/")
    if PurePosixPath(value).is_absolute() or any(
        not part or part in {".", ".."} or part.endswith((".", " "))
        or any(ord(c) < 32 or c in '<>:"|?*' for c in part)
        or _DEVICE.fullmatch(part)
        for part in parts
    ):
        raise ValueError("invalid managed relative path")
    return tuple(parts)


def identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,191}", value):
        raise ValueError("invalid transfer identity")
    if len(portable_parts(value)) != 1:
        raise ValueError("invalid transfer identity")
    return value


def managed_path(root: Path, *relative: str) -> Path:
    """Never follow symlinks/junctions, including links pointing inside root.

    The deployment must ACL-protect the root from untrusted local writers;
    network clients never supply an absolute root or create links.
    """
    root = root.absolute()
    target = root.joinpath(*(part for value in relative for part in portable_parts(value)))
    for item in (*reversed(target.parents), target):
        try:
            metadata = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or (
            getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise ValueError("managed transfer paths cannot contain links or reparse points")
    target.resolve().relative_to(root.resolve())
    return target


def verify_file(path: Path, size: int, digest: str) -> None:
    if not path.is_file() or path.stat().st_size != size or sha256_file(path) != digest:
        raise ValueError("managed file size or SHA256 mismatch")


def publish_new_file(temporary: Path, destination: Path) -> None:
    """Same-volume atomic no-clobber publication (NTFS/POSIX hard link).

    Fail closed on unsupported filesystems instead of emulating with an
    overwrite-prone check/rename. Only the caller-owned temporary is removed.
    """
    os.link(temporary, destination)
