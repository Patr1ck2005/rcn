"""Portable data-only COMSOL requests prepared by an origin-side compiler.

No Workbench modules or scientific compilation run on a member computer.  The
manifest freezes the compiled request and exact input bytes; an operational
partition choice is recorded separately by submission_operations.
"""
from __future__ import annotations

import hashlib
import json
import os
import errno
from pathlib import Path
import re
import shutil
import stat
import tempfile
from typing import Literal
import zipfile
import yaml

from pydantic import BaseModel, ConfigDict, Field, model_validator, model_serializer

from .hashing import canonical_json_bytes, sha256_file, sha256_value
from .models import FileRecord, PartitionPlan, PartitionRequest
from .origin import OriginSpool, _WORKBENCH_COMSOL_PROFILES
from .origin_transfer import portable_parts, identifier

MANIFEST_NAME = "submission-package.json"
MAX_PACKAGE_FILES = 512
MAX_PACKAGE_BYTES = 64 * 1024**3
MAX_MANIFEST_BYTES = 32 * 1024**2
_DIGEST = r"^[0-9a-f]{64}$"
_EXECUTABLE_SUFFIXES = {".exe", ".dll", ".com", ".bat", ".cmd", ".ps1", ".py", ".pyc", ".pyd", ".js", ".vbs", ".msi", ".sh", ".jar", ".class", ".lnk", ".reg", ".scr"}
_SECRET_KEYS = {"password", "private_key", "client_secret", "access_token", "refresh_token", "authorization", "ssh_password", "api_token", "node_token"}


def _safe_input_name(value: str) -> str:
    parts = portable_parts(value)
    if "/".join(parts) != value or not value.startswith("inputs/"):
        raise ValueError("package files must use canonical portable inputs/ paths")
    if Path(value).suffix.casefold() in _EXECUTABLE_SUFFIXES:
        raise ValueError("submission packages contain data files, not executable code")
    name = parts[-1].casefold()
    if name in {".env", "id_rsa", "id_ed25519", "credentials", "credentials.json"} or name.endswith((".pem", ".key", ".pfx", ".p12")):
        raise ValueError("credentials and private keys must not be packaged")
    return value


def _reject_secrets(value, _seen=None, _depth=0) -> None:
    if _depth > 64:
        raise ValueError("scientific configuration nesting is too deep")
    _seen = set() if _seen is None else _seen
    if isinstance(value, (dict, list)):
        if id(value) in _seen:
            return
        _seen.add(id(value))
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).casefold().replace("-", "_") in _SECRET_KEYS and item not in (None, "", [], {}):
                raise ValueError("submission data contains a credential field")
            _reject_secrets(item, _seen, _depth + 1)
    elif isinstance(value, list):
        for item in value:
            _reject_secrets(item, _seen, _depth + 1)
    elif isinstance(value, str) and ("-----BEGIN " in value and "PRIVATE KEY-----" in value or value.startswith("Bearer ")):
        raise ValueError("submission data contains a private credential")


def science_contract(request: PartitionRequest) -> dict:
    payload = request.model_dump(mode="json")
    return {name: payload[name] for name in (
        "origin_submitter_id", "origin_adapter_id", "user_id", "project_id", "execution_profile_id",
        "campaign_id", "campaign_task_id", "recipe_kind", "study_kind", "template_role", "template_sha256",
        "template_parameter_evidence", "source_spec_sha256", "output_contract_sha256", "items", "input_manifest",
    )}


def request_payload(request: PartitionRequest) -> dict:
    """Model sets must have stable ordering across distinct member processes."""
    result = request.model_dump(mode="json")
    result["required_capabilities"] = sorted(result["required_capabilities"])
    result["allowed_solver_variants"] = sorted(result["allowed_solver_variants"])
    return result


def _publish_local_data(temporary: Path, target: Path) -> None:
    """No-overwrite publication, including member USB volumes without links."""
    try:
        os.link(temporary, target)
    except OSError as exc:
        if os.name != "nt" or exc.errno not in {errno.EPERM, errno.EINVAL, errno.ENOTSUP}:
            raise
        # Windows rename fails if the destination exists. Both paths are on
        # the same selected volume; unlike replace(), it cannot erase data.
        os.rename(temporary, target)


class SubmissionPackageManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    request: PartitionRequest
    files: list[FileRecord] = Field(min_length=1, max_length=MAX_PACKAGE_FILES)
    origin_layout: dict[str, str]
    source_request_hash: str = Field(pattern=_DIGEST)
    request_sha256: str = Field(pattern=_DIGEST)
    input_manifest_sha256: str = Field(pattern=_DIGEST)
    science_contract_sha256: str = Field(pattern=_DIGEST)
    package_contents_sha256: str = Field(pattern=_DIGEST)

    @model_serializer(mode="wrap")
    def serialize_canonical_request(self, serializer):
        result = serializer(self)
        result["request"] = request_payload(self.request)
        return result

    def contents_payload(self) -> dict:
        return self.model_dump(mode="json", exclude={"package_contents_sha256"})

    @model_validator(mode="after")
    def validate_bindings(self):
        if self.request.execution_profile_id not in _WORKBENCH_COMSOL_PROFILES:
            raise ValueError("member packages require a registered fixed COMSOL profile")
        expected_kind = ("workbench_comsol_scan_items" if self.request.execution_profile_id == "workbench-comsol-scan-v1" else "workbench_comsol_recipe_items")
        if self.request.unit_payload_kind != expected_kind:
            raise ValueError("compiled request has an unsupported COMSOL unit payload kind")
        identifier(self.request.origin_submitter_id)
        identifier(self.request.project_id)
        _reject_secrets(self.request.model_dump(mode="json"))
        names = [_safe_input_name(record.relative_path) for record in self.files]
        if names != sorted(names) or len(set(name.casefold() for name in names)) != len(names):
            raise ValueError("package inputs must be sorted and unambiguous on Windows")
        if sum(record.size_bytes for record in self.files) > MAX_PACKAGE_BYTES:
            raise ValueError("submission package exceeds the input size limit")
        records = [record.model_dump(mode="json") for record in self.files]
        request_records = sorted((record.model_dump(mode="json") for record in self.request.input_manifest), key=lambda record: record["relative_path"])
        if records != request_records:
            raise ValueError("package files must exactly match the compiled request input_manifest")
        if set(self.origin_layout) != {"project_yaml", "scan_spec", "template"}:
            raise ValueError("package requires exactly the three COMSOL origin input roles")
        if set(self.origin_layout.values()) != set(names) or len(names) != 3:
            raise ValueError("COMSOL package roles must cover all three declared inputs")
        if self.origin_layout["project_yaml"] != "inputs/project.yaml" or self.origin_layout["template"] != "inputs/template.mph":
            raise ValueError("COMSOL project and template logical input paths do not match OriginSpool")
        if len(portable_parts(self.origin_layout["scan_spec"])) != 2:
            raise ValueError("COMSOL scan logical input must be directly under inputs/")
        if self.source_request_hash != self.request.request_hash:
            raise ValueError("source request hash differs from the compiled request")
        if self.request_sha256 != sha256_value(request_payload(self.request)):
            raise ValueError("compiled request SHA256 mismatch")
        if self.input_manifest_sha256 != sha256_value(records):
            raise ValueError("input manifest SHA256 mismatch")
        if self.science_contract_sha256 != sha256_value(science_contract(self.request)):
            raise ValueError("scientific contract SHA256 mismatch")
        if self.package_contents_sha256 != sha256_value(self.contents_payload()):
            raise ValueError("package contents SHA256 mismatch")
        template = next(record for record in self.files if record.relative_path == self.origin_layout["template"])
        if self.request.template_sha256 and self.request.template_sha256 != template.sha256:
            raise ValueError("package template differs from the scientific contract")
        return self


def _request(value) -> PartitionRequest:
    if isinstance(value, PartitionPlan):
        return value.request.model_copy(deep=True)
    if isinstance(value, PartitionRequest):
        return value.model_copy(deep=True)
    if isinstance(value, (str, Path)):
        value = json.loads(Path(value).read_text(encoding="utf-8-sig"))
    if isinstance(value, dict) and "request" in value and "plan_id" in value:
        value = value["request"]
    return PartitionRequest.model_validate(value)


def _check_data(handle, name: str, size: int) -> None:
    prefix = handle.read(min(size, 4096))
    if prefix.startswith((b"MZ", b"\x7fELF", b"#!")):
        raise ValueError("an executable was disguised as a package data file")
    if b"PRIVATE KEY-----" in prefix:
        raise ValueError("private key was disguised as a package data file")
    if Path(name).suffix.casefold() in {".json", ".yaml", ".yml"}:
        if size > MAX_MANIFEST_BYTES:
            raise ValueError("scientific text configuration is too large")
        raw = prefix + handle.read()
        if b"PRIVATE KEY-----" in raw or re.search(rb"(?im)^\s*(?:password|private_key|client_secret|access_token|refresh_token|api_token|node_token)\s*:\s*[^\s#]", raw):
            raise ValueError("scientific configuration contains a credential")
        if Path(name).suffix.casefold() == ".json":
            _reject_secrets(json.loads(raw.decode("utf-8-sig")))
        else:
            try:
                _reject_secrets(yaml.safe_load(raw.decode("utf-8-sig")))
            except yaml.YAMLError as exc:
                raise ValueError("scientific YAML must be data-only and parseable") from exc


def build_submission_package(destination: str | Path, request_or_plan, input_root: str | Path,
                             *, origin_layout: dict[str, str] | None = None,
                             input_files: dict[str, str | Path] | None = None) -> SubmissionPackageManifest:
    """Package an already compiled request; never rewrite its scientific data."""
    request = _request(request_or_plan)
    records = sorted(request.input_manifest, key=lambda record: record.relative_path)
    if origin_layout is None:
        scan = [record.relative_path for record in records if record.relative_path not in {"inputs/project.yaml", "inputs/template.mph"}]
        if len(scan) != 1:
            raise ValueError("explicit origin_layout required for ambiguous COMSOL inputs")
        origin_layout = {"project_yaml": "inputs/project.yaml", "scan_spec": scan[0], "template": "inputs/template.mph"}
    payload = dict(schema_version=1, request=request_payload(request), files=[record.model_dump(mode="json") for record in records],
                   origin_layout=origin_layout, source_request_hash=request.request_hash,
                   request_sha256=sha256_value(request_payload(request)), input_manifest_sha256=sha256_value([record.model_dump(mode="json") for record in records]),
                   science_contract_sha256=sha256_value(science_contract(request)))
    payload["package_contents_sha256"] = sha256_value(payload)
    manifest = SubmissionPackageManifest.model_validate(payload)
    root = Path(input_root).resolve()
    sources = {}
    if input_files is not None and set(input_files) != {record.relative_path for record in records}:
        raise ValueError("input_files mapping must exactly cover the declared inputs")
    for record in records:
        source = Path(input_files[record.relative_path]) if input_files is not None else root.joinpath(*portable_parts(record.relative_path))
        if input_files is None:
            source.resolve().relative_to(root)
        if source.is_symlink() or not source.is_file():
            raise ValueError("input files must be ordinary readable files")
        if source.stat().st_size != record.size_bytes or sha256_file(source) != record.sha256:
            raise ValueError(f"input SHA256 or size mismatch: {record.relative_path}")
        with source.open("rb") as handle:
            _check_data(handle, record.relative_path, record.size_bytes)
        sources[record.relative_path] = source
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".submission-", suffix=".zip", dir=target.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            for member, source in sources.items():
                info = zipfile.ZipInfo(member, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                with source.open("rb") as input_stream, archive.open(info, "w", force_zip64=True) as output_stream:
                    shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
            manifest_info = zipfile.ZipInfo(MANIFEST_NAME, date_time=(1980, 1, 1, 0, 0, 0))
            manifest_info.compress_type = zipfile.ZIP_DEFLATED
            manifest_info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(manifest_info, canonical_json_bytes(manifest.model_dump(mode="json")))
        inspect_submission_package(temporary)
        if target.exists():
            if sha256_file(target) != sha256_file(temporary):
                raise FileExistsError("destination contains a different submission package")
        else:
            _publish_local_data(temporary, target)
        return manifest
    finally:
        temporary.unlink(missing_ok=True)


def _validated_archive(archive: zipfile.ZipFile, expected_actor_id=None) -> tuple[SubmissionPackageManifest, dict[str, zipfile.ZipInfo]]:
    infos = archive.infolist()
    if not 1 < len(infos) <= MAX_PACKAGE_FILES + 1:
        raise ValueError("invalid submission package member count")
    members = {}
    folded = set()
    for info in infos:
        portable_parts(info.filename)
        if info.is_dir() or info.filename.casefold() in folded or (info.external_attr >> 16) & 0o170000 == stat.S_IFLNK or info.flag_bits & 1:
            raise ValueError("submission package contains an ambiguous, encrypted or linked member")
        folded.add(info.filename.casefold())
        members[info.filename] = info
    if sum(info.file_size for info in infos) > MAX_PACKAGE_BYTES + MAX_MANIFEST_BYTES:
        raise ValueError("submission package exceeds its expanded size limit")
    if MANIFEST_NAME not in members or members[MANIFEST_NAME].file_size > MAX_MANIFEST_BYTES:
        raise ValueError("submission package manifest is missing or too large")
    manifest = SubmissionPackageManifest.model_validate_json(archive.read(MANIFEST_NAME))
    if expected_actor_id is not None and manifest.request.user_id != expected_actor_id:
        raise PermissionError("submission package belongs to another member")
    if set(members) != {MANIFEST_NAME, *(record.relative_path for record in manifest.files)}:
        raise ValueError("submission archive does not exactly match its declared files")
    for record in manifest.files:
        info = members[record.relative_path]
        if info.file_size != record.size_bytes:
            raise ValueError("submission package input size mismatch")
        with archive.open(info) as handle:
            digest = hashlib.sha256()
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
            if digest.hexdigest() != record.sha256:
                raise ValueError("submission package input SHA256 mismatch")
        with archive.open(info) as handle:
            _check_data(handle, record.relative_path, record.size_bytes)
    return manifest, members


def inspect_submission_package(path: str | Path, *, expected_actor_id: str | None = None) -> SubmissionPackageManifest:
    with zipfile.ZipFile(path) as archive:
        return _validated_archive(archive, expected_actor_id)[0]


def extract_submission_package(path: str | Path, destination: str | Path, *, expected_actor_id: str | None = None) -> SubmissionPackageManifest:
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as archive:
        manifest, members = _validated_archive(archive, expected_actor_id)
        for record in manifest.files:
            target = root.joinpath(*portable_parts(record.relative_path))
            target.resolve().relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if not target.is_file() or target.is_symlink() or target.stat().st_size != record.size_bytes or sha256_file(target) != record.sha256:
                    raise FileExistsError("existing package extraction differs from the original input")
                continue
            fd, name = tempfile.mkstemp(prefix=".input-", dir=target.parent)
            temporary = Path(name)
            try:
                with os.fdopen(fd, "wb") as output, archive.open(members[record.relative_path]) as source:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                _publish_local_data(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
    return manifest


def prepare_submission_bundles(package_path: str | Path, operation, spool_root: str | Path, runtime_version: str,
                               *, content_addressed: bool = True) -> list[Path]:
    from .submission_operations import SubmissionOperation
    from .partitioning import job_from_confirmed_plan
    operation = SubmissionOperation.model_validate(operation)
    if operation.job_id is None or operation.plan.status != "confirmed":
        raise ValueError("submission operation must be confirmed before origin sealing")
    manifest = inspect_submission_package(package_path, expected_actor_id=operation.actor_id)
    if manifest.package_contents_sha256 != operation.package_contents_sha256:
        raise ValueError("submission package differs from the durable operation")
    input_root = Path(spool_root) / ".submission-inputs" / operation.operation_id
    extract_submission_package(package_path, input_root, expected_actor_id=operation.actor_id)
    job = job_from_confirmed_plan(operation.plan)
    job.job_id = operation.job_id
    # The operation owns the operational identity; scientific bytes remain unchanged.
    job.request_hash = operation.job_request_hash or job.request_hash
    return OriginSpool(spool_root).publish_comsol(job=job, project_root=input_root,
        project_yaml=input_root / manifest.origin_layout["project_yaml"], scan_spec=input_root / manifest.origin_layout["scan_spec"],
        template=input_root / manifest.origin_layout["template"], runtime_version=runtime_version, content_addressed=content_addressed)
