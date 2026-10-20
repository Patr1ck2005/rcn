"""Exact, operator-published read mappings for incremental spool migration.

These immutable per-Attempt records are metadata, not custody receipts or GC
authorization. The operator must fully verify both inventories and keep the
target stable before publishing a record, then unlink only its exact verified
source files. Network clients cannot register mappings. Active writes keep
using the configured spool; only absent files in its original default root
may use an explicitly enrolled target.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from .hashing import sha256_value
from .origin_transfer import identifier, managed_path, portable_parts
from .storage_ops import _write_json
from .storage_roots import StoreBinding, StorageRootError, absolute_root, current_host_id, reject_reparse_path


MAX_RELOCATION_BYTES = 4 * 1024 * 1024
_FIELDS = {"format", "host_id", "operation_id", "actor_id", "registered_at", "job_id",
           "request_hash", "origin_submitter_id", "project_id", "work_unit_id",
           "producer_attempt_id", "producer_external_id", "manifest_sha256", "source_root",
           "source_directory", "target_directory", "target_binding", "files"}


def _invalid(message):
    return StorageRootError("spool_relocation_invalid", message)


def relocation_path(control_root, job_id, unit_id, attempt_id):
    """Lookup one Unit directly; never scan a global inventory on HTTP reads."""
    return managed_path(Path(control_root), "operator-actions", "spool-relocations",
                        identifier(job_id), identifier(unit_id), identifier(attempt_id) + ".json")


def _read_record(path):
    reject_reparse_path(path)
    try:
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_RELOCATION_BYTES:
            raise ValueError("relocation metadata is not a bounded regular file")
        with path.open("rb") as stream:
            raw = stream.read(MAX_RELOCATION_BYTES + 1)
        if len(raw) > MAX_RELOCATION_BYTES:
            raise ValueError("relocation metadata exceeded its size bound")
        after = path.stat()
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError("relocation metadata changed during read")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("relocation metadata must be an object")
        return value, hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError) as exc:
        raise _invalid("cannot read immutable relocation metadata") from exc


@dataclass(frozen=True)
class UnitRelocation:
    payload: dict
    source: Path
    target: Path
    binding: StoreBinding
    files: dict

    @classmethod
    def from_payload(cls, control_root, payload):
        try:
            return cls._from_payload(control_root, payload)
        except StorageRootError:
            raise
        except (TypeError, ValueError) as exc:
            raise _invalid("invalid relocation identity or managed path") from exc

    @classmethod
    def _from_payload(cls, control_root, payload):
        if (not isinstance(payload, dict) or set(payload) != _FIELDS
                or type(payload["format"]) is not int or payload["format"] != 1):
            raise _invalid("unsupported relocation metadata fields")
        for name in _FIELDS - {"format", "target_binding", "files"}:
            if not isinstance(payload[name], str) or not payload[name].strip():
                raise _invalid("relocation identity must be explicit")
        for name in ("request_hash", "manifest_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", payload[name]):
                raise _invalid("invalid relocation digest")
        for name in ("job_id", "origin_submitter_id", "work_unit_id", "producer_attempt_id"):
            identifier(payload[name])
        source_root = absolute_root(payload["source_root"])
        if source_root != Path(control_root).absolute() / "origin-spool":
            raise _invalid("relocation source must be the original default spool")
        source = absolute_root(payload["source_directory"])
        expected = managed_path(source_root, payload["origin_submitter_id"], "incoming",
                                payload["job_id"], payload["work_unit_id"], payload["producer_attempt_id"])
        if source != expected:
            raise _invalid("relocation source directory does not match its producer")
        binding = StoreBinding.from_dict(payload["target_binding"])
        if (binding.logical_store_id != "origin_spool" or payload["host_id"] != current_host_id()
                or binding.host_id != payload["host_id"]):
            raise _invalid("relocation target role or host changed")
        if (binding.root.is_relative_to(source_root) or source_root.is_relative_to(binding.root)
                or Path(control_root).absolute().is_relative_to(binding.root)):
            raise _invalid("relocation target overlaps the control plane or source")
        target = absolute_root(payload["target_directory"])
        expected_target = managed_path(binding.root, source.relative_to(source_root).as_posix())
        if target != expected_target:
            raise _invalid("relocation target directory does not match the original layout")
        if not isinstance(payload["files"], list) or not payload["files"]:
            raise _invalid("relocation requires a complete file inventory")
        files = {}
        folded = set()
        for record in payload["files"]:
            if (not isinstance(record, dict) or set(record) != {"relative_path", "size_bytes", "sha256"}
                    or type(record["size_bytes"]) is not int or record["size_bytes"] < 0
                    or not isinstance(record["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])):
                raise _invalid("invalid relocation inventory record")
            portable_parts(record["relative_path"])
            name = record["relative_path"]
            if name.casefold() in folded:
                raise _invalid("ambiguous relocation inventory")
            folded.add(name.casefold())
            files[name] = record
        return cls(payload, source, target, binding, files)

    def validate_producer(self, job, unit, attempt, manifest, source_directory):
        value = self.payload
        if (value["job_id"] != job.job_id or value["request_hash"] != job.request_hash
                or value["origin_submitter_id"] != job.origin_submitter_id or value["project_id"] != job.project_id
                or value["work_unit_id"] != unit.work_unit_id or value["producer_attempt_id"] != attempt.attempt_id
                or value["producer_external_id"] != attempt.external_run_id
                or unit.status != "completed" or attempt.state != "completed" or attempt.collected_at is None
                or manifest.job_id != job.job_id or manifest.work_unit_id != unit.work_unit_id
                or manifest.producer.get("attempt_id") != attempt.attempt_id
                or (manifest.producer.get("external_run_id") is not None
                    and manifest.producer["external_run_id"] != attempt.external_run_id)
                or value["manifest_sha256"] != sha256_value(manifest.model_dump(mode="json"))
                or self.source != Path(source_directory).absolute()):
            raise StorageRootError("spool_relocation_binding_mismatch", "relocation no longer matches its exact producer")
        for record in manifest.files:
            if self.files.get(record.relative_path) != {"relative_path": record.relative_path,
                    "size_bytes": record.size_bytes, "sha256": record.sha256}:
                raise StorageRootError("spool_relocation_binding_mismatch", "relocation inventory differs from the manifest")


def publish_relocation(control_root, payload):
    """Atomic immutable metadata publication after operator-owned SHA proofs.

    This function does not copy, hash or delete scientific files. Its caller
    must hold stable verified targets and publish BEFORE unlinking source bytes.
    Repeating an identical record is safe; a conflicting record cannot replace it.
    """
    relocation = UnitRelocation.from_payload(control_root, payload)
    if len(json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")) + 1 > MAX_RELOCATION_BYTES:
        raise _invalid("relocation metadata exceeds its size bound")
    relocation.binding.validate()
    path = relocation_path(control_root, payload["job_id"], payload["work_unit_id"], payload["producer_attempt_id"])
    reject_reparse_path(path.parent, must_exist=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        _write_json(path, payload, create_only=True)
    except FileExistsError:
        existing, _ = _read_record(path)
        if existing != payload:
            raise StorageRootError("spool_relocation_conflict", "an immutable relocation already exists")
    return path


class SpoolRelocationRegistry:
    def __init__(self, control_root):
        self.control_root = Path(control_root).absolute()

    def resolve_files(self, *, job, unit, attempt, manifest, source_directory, records):
        """Prefer each original file; enroll only exact missing counterparts."""
        paths = [managed_path(source_directory, record.relative_path) for record in records]
        missing = []
        for index, path in enumerate(paths):
            try:
                path.lstat()
            except FileNotFoundError:
                missing.append(index)
        if not missing:
            return paths, None
        receipt_path = relocation_path(self.control_root, job.job_id, unit.work_unit_id, attempt.attempt_id)
        try:
            receipt_path.lstat()
        except FileNotFoundError:
            return paths, None
        payload, receipt_sha = _read_record(receipt_path)
        relocation = UnitRelocation.from_payload(self.control_root, payload)
        relocation.validate_producer(job, unit, attempt, manifest, source_directory)
        relocation.binding.validate()
        targets = []
        for index in missing:
            selected = managed_path(relocation.target, records[index].relative_path)
            reject_reparse_path(selected)
            paths[index] = selected
            targets.append(selected)

        def validate():
            _, current_sha = _read_record(receipt_path)
            if current_sha != receipt_sha:
                raise StorageRootError("spool_relocation_changed", "immutable relocation metadata changed during a read")
            relocation.binding.validate()
            for selected in targets:
                reject_reparse_path(selected)

        return paths, validate
