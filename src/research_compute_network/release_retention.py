"""Preview and stage old release transactions without destructive deletion."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_record(root: Path) -> dict[str, Any]:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    records = [
        {"path": path.relative_to(root).as_posix(), "size_bytes": path.stat().st_size, "sha256": _sha256_file(path)}
        for path in files
    ]
    identity = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "deployment_id": root.name,
        "size_bytes": sum(record["size_bytes"] for record in records),
        "sha256": hashlib.sha256(identity).hexdigest(),
        "files": records,
    }


def _manifest(path: Path) -> dict[str, Any]:
    manifest_path = path / "deployment-manifest.json"
    if not manifest_path.is_file():
        return {"state": "unknown", "prepared_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()}
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"state": "invalid", "prepared_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()}


def preview_release_retention(state_root: Path) -> dict[str, Any]:
    state_root = state_root.resolve()
    deployments_root = state_root / "releases" / "deployments"
    pin_path = state_root / "releases" / "pinned.json"
    pinned = set(json.loads(pin_path.read_text(encoding="utf-8")).get("deployment_ids", [])) if pin_path.is_file() else set()
    pointer_path = state_root / "runtime" / "current.json"
    current = None
    if pointer_path.is_file():
        current = str(json.loads(pointer_path.read_text(encoding="utf-8")).get("deployment_id") or "")
    entries = []
    if deployments_root.exists():
        for path in deployments_root.iterdir():
            if path.is_dir():
                entries.append((path, _manifest(path)))
    entries.sort(key=lambda item: str(item[1].get("prepared_at") or ""), reverse=True)
    successful = [path.name for path, item in entries if item.get("state") in {"promoted", "verified"}]
    failed = [
        path.name
        for path, item in entries
        if item.get("state") in {"failed", "rollback_failed", "invalid"}
        or (
            item.get("state") == "rolled_back"
            and isinstance(item.get("rollback"), dict)
            and item["rollback"].get("automatic") is True
        )
    ]
    protected = set(pinned)
    if current:
        protected.add(current)
    protected.update(successful[:2])
    protected.update(failed[:1])
    candidates = []
    for path, item in entries:
        if path.name in protected:
            continue
        record = _tree_record(path)
        record.update({"state": item.get("state"), "reason": "outside 2 successful + 1 failed + pinned retention"})
        candidates.append(record)
    confirmation_payload = json.dumps(
        [{key: item[key] for key in ("deployment_id", "size_bytes", "sha256", "reason")} for item in candidates],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "schema_version": 1,
        "state_root": str(state_root),
        "protected": sorted(protected),
        "candidates": candidates,
        "candidate_bytes": sum(item["size_bytes"] for item in candidates),
        "confirmation_hash": hashlib.sha256(confirmation_payload).hexdigest(),
    }


def pin_release(state_root: Path, deployment_id: str, *, pinned: bool = True) -> dict[str, Any]:
    state_root = state_root.resolve()
    path = state_root / "releases" / "pinned.json"
    values = set(json.loads(path.read_text(encoding="utf-8")).get("deployment_ids", [])) if path.is_file() else set()
    if pinned:
        values.add(deployment_id)
    else:
        values.discard(deployment_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": 1, "deployment_ids": sorted(values)}, indent=2) + "\n", encoding="utf-8")
    return {"deployment_id": deployment_id, "pinned": pinned, "all_pinned": sorted(values)}


def stage_release_candidates(state_root: Path, confirmation_hash: str) -> dict[str, Any]:
    preview = preview_release_retention(state_root)
    if confirmation_hash != preview["confirmation_hash"]:
        raise ValueError("confirmation hash does not match the current retention preview")
    staging_root = state_root.resolve() / "archive-staging" / f"release-retention-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    staging_root.mkdir(parents=True, exist_ok=False)
    moved = []
    for candidate in preview["candidates"]:
        source = state_root.resolve() / "releases" / "deployments" / candidate["deployment_id"]
        target = staging_root / candidate["deployment_id"]
        shutil.move(str(source), str(target))
        moved.append(candidate["deployment_id"])
    manifest = preview | {"staged_at": datetime.now(timezone.utc).isoformat(), "moved": moved}
    (staging_root / "archive-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (staging_root / "README.md").write_text(
        "# RCN release archive staging\n\nThese release transactions were moved after an explicit retention preview. "
        "Upload and verify the archive before deleting this directory locally. Current, previous rollback, latest failed, and pinned releases were excluded.\n",
        encoding="utf-8",
    )
    return {"staging_root": str(staging_root), "moved": moved, "candidate_bytes": preview["candidate_bytes"]}
