"""Artifact-manifest creation and origin-side verification."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from .hashing import sha256_file
from .models import ArtifactManifest, FileRecord


class ArtifactValidation(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)


def file_record(path: str | Path, *, relative_path: str, media_type: str = "application/octet-stream") -> FileRecord:
    source = Path(path)
    return FileRecord(
        relative_path=relative_path,
        size_bytes=source.stat().st_size,
        sha256=sha256_file(source),
        media_type=media_type,
    )


def validate_artifact_manifest(root: str | Path, manifest: ArtifactManifest) -> ArtifactValidation:
    base = Path(root).resolve()
    errors: list[str] = []
    seen: set[str] = set()
    for record in manifest.files:
        if record.relative_path in seen:
            errors.append(f"duplicate manifest path: {record.relative_path}")
            continue
        seen.add(record.relative_path)
        candidate = (base / record.relative_path).resolve()
        try:
            candidate.relative_to(base)
        except ValueError:
            errors.append(f"artifact escapes staging root: {record.relative_path}")
            continue
        if not candidate.is_file():
            errors.append(f"missing artifact: {record.relative_path}")
            continue
        actual_size = candidate.stat().st_size
        if actual_size != record.size_bytes:
            errors.append(
                f"size mismatch for {record.relative_path}: expected {record.size_bytes}, got {actual_size}"
            )
            continue
        actual_hash = sha256_file(candidate)
        if actual_hash != record.sha256:
            errors.append(f"sha256 mismatch for {record.relative_path}")
    return ArtifactValidation(valid=not errors, errors=errors)
