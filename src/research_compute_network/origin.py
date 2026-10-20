"""Origin-owned bundle spool for fixed-profile Dispatcher handoff.

Bundle bytes stay on an explicitly configured filesystem path.  The Control
Plane stores only Job, attempt and manifest metadata.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import stat
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator, Literal

from pydantic import BaseModel, Field, model_validator

from .artifacts import file_record
from .hashing import canonical_json_bytes, sha256_file, sha256_value
from .origin_transfer import managed_path, portable_parts, publish_new_file
from .origin_assets import ASSET_MARKER, ASSET_MARKER_BYTES, TransferAssetValidationCache, publish_asset, verify_asset
from .models import (
    Assignment,
    FileRecord,
    JobEnvelope,
    MachineExecutionConfig,
    ResourceRequest,
    WorkUnit,
)
from .profiles import (
    PROJECT_WORKER_V1,
    WORKBENCH_COMSOL_EIGEN_V2,
    WORKBENCH_COMSOL_EIGEN_V4,
    WORKBENCH_COMSOL_FREQUENCY_V1,
    WORKBENCH_COMSOL_SCAN_V1,
    WORKBENCH_COMSOL_STUDY_V1,
    WORKBENCH_COMSOL_STUDY_V2,
    WORKBENCH_COMSOL_TEMPLATE_BUILD_V1,
    WORKBENCH_COMSOL_SAVED_READOUT_V1,
)
from .parameter_guard import validate_job_parameter_contract, validate_unit_parameter_contract
from .ssh_bundle import build_comsol_unit_bundle, build_project_worker_unit_bundle
from .schedulers.base import PreLaunchSubmissionError
from .volume_budget import VolumeBudgetError


ORIGIN_BUNDLE_SCHEMA = 1
MAX_BUNDLE_FILES = 10_000
MAX_BUNDLE_BYTES = 8 * 1024 * 1024 * 1024
BUNDLE_BUILD_METADATA_MARGIN_BYTES = 8 * 1024**2
_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,191}")
_WORKBENCH_COMSOL_PROFILES = {
    WORKBENCH_COMSOL_SCAN_V1.profile_id,
    WORKBENCH_COMSOL_EIGEN_V2.profile_id,
    "workbench-comsol-eigen-v3",
    WORKBENCH_COMSOL_EIGEN_V4.profile_id,
    WORKBENCH_COMSOL_FREQUENCY_V1.profile_id,
    "workbench-comsol-frequency-v2",
    WORKBENCH_COMSOL_STUDY_V1.profile_id,
    WORKBENCH_COMSOL_STUDY_V2.profile_id,
    WORKBENCH_COMSOL_TEMPLATE_BUILD_V1.profile_id,
    WORKBENCH_COMSOL_SAVED_READOUT_V1.profile_id,
}


def _safe_component(value: str, label: str) -> str:
    if not _SAFE_COMPONENT.fullmatch(value):
        raise ValueError(f"{label} contains unsafe filesystem characters")
    return value


def _relative_path(value: str, label: str) -> PurePosixPath:
    if "\\" in value or ":" in value or "\x00" in value:
        raise ValueError(f"{label} must use a portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts or value in {"", "."}:
        raise ValueError(f"{label} must be a non-empty relative path")
    return path


class OriginBundleDescriptor(BaseModel):
    schema_version: Literal[1] = 1
    origin_submitter_id: str
    project_id: str
    job_id: str
    work_unit_id: str
    profile_id: str
    runtime_version: str
    job_request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_data: dict[str, Any]
    files: list[FileRecord]
    bundle_request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_files(self) -> "OriginBundleDescriptor":
        names = [record.relative_path.casefold() for record in self.files]
        if len(names) != len(set(names)):
            raise ValueError("origin bundle descriptor contains duplicate file paths")
        return self

    def hash_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"bundle_request_hash"})


class OriginBundleStatus(BaseModel):
    path: str
    ready: bool
    profile_id: str | None = None
    runtime_version: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None


class OriginSpool:
    """Filesystem handoff owned jointly by an origin adapter and Dispatcher."""

    def __init__(self, root: str | Path, *, transfer_asset_cache=None, storage_validator=None,
                 volume_budget=None) -> None:
        self.root = Path(root).resolve()
        self._transfer_asset_cache = transfer_asset_cache
        self._storage_validator = storage_validator
        self._volume_budget = volume_budget
        # A missing bulk-data disk must not prevent metadata/API startup.
        # Configured roots are checked at IO time and never recreated elsewhere.
        if storage_validator is None:
            self.root.mkdir(parents=True, exist_ok=True)

    def _guard_storage(self) -> None:
        if self._storage_validator is not None:
            selected = Path(self._storage_validator()).absolute()
            if selected != self.root.absolute():
                raise ValueError("origin spool storage binding changed; reload the registered root")

    def outgoing_path(self, job: JobEnvelope, unit: WorkUnit) -> Path:
        self._guard_storage()
        origin = _safe_component(job.origin_submitter_id, "origin submitter ID")
        job_id = _safe_component(job.job_id, "job ID")
        unit_id = _safe_component(unit.work_unit_id, "work-unit ID")
        return self.root / origin / "outgoing" / job_id / f"{unit_id}.zip"

    def incoming_path(self, job: JobEnvelope, unit: WorkUnit, attempt_id: str) -> Path:
        self._guard_storage()
        origin = _safe_component(job.origin_submitter_id, "origin submitter ID")
        job_id = _safe_component(job.job_id, "job ID")
        unit_id = _safe_component(unit.work_unit_id, "work-unit ID")
        attempt = _safe_component(attempt_id, "attempt ID")
        destination = self.root / origin / "incoming" / job_id / unit_id / attempt
        destination.resolve().relative_to(self.root)
        return destination

    def status(self, job: JobEnvelope, unit: WorkUnit) -> OriginBundleStatus:
        path = self.outgoing_path(job, unit)
        if not path.is_file():
            return OriginBundleStatus(path=str(path), ready=False)
        descriptor = self.validate(job, unit)
        return OriginBundleStatus(
            path=str(path),
            ready=True,
            profile_id=descriptor.profile_id,
            runtime_version=descriptor.runtime_version,
            size_bytes=path.stat().st_size,
            sha256=sha256_file(path),
        )

    def publish_comsol(
        self,
        *,
        job: JobEnvelope,
        project_root: str | Path,
        project_yaml: str | Path,
        scan_spec: str | Path,
        template: str | Path,
        runtime_version: str,
        work_unit_id: str | None = None,
        content_addressed: bool = False,
    ) -> list[Path]:
        if job.execution_profile_id not in _WORKBENCH_COMSOL_PROFILES:
            raise ValueError("COMSOL origin preparation requires a registered Workbench COMSOL profile")
        root = Path(project_root).resolve()
        if not root.is_dir():
            raise FileNotFoundError(root)
        project_yaml_path = Path(project_yaml).resolve()
        project_yaml_path.relative_to(root)
        spec_path = Path(scan_spec)
        if not spec_path.is_absolute():
            spec_path = root / spec_path
        spec_path = spec_path.resolve()
        spec_relative = spec_path.relative_to(root)
        template = Path(template).resolve()
        if not project_yaml_path.is_file() or not spec_path.is_file() or not template.is_file():
            raise FileNotFoundError("COMSOL origin inputs must be readable files")
        try:
            template_relative = template.relative_to(root)
            template_archive = f"project/{template_relative.as_posix()}"
        except ValueError:
            # Some Workbench projects deliberately reference a shared,
            # human-controlled template outside their project directory. Keep
            # that file in the sealed origin bundle under a neutral name.
            template_relative = None
            template_archive = "project/__template__.mph"

        source_files = {
            "project/project.yaml": project_yaml_path,
            f"project/{spec_relative.as_posix()}": spec_path,
            template_archive: template,
        }
        logical_inputs = {
            "inputs/project.yaml": project_yaml_path,
            f"inputs/{spec_relative.name}": spec_path,
            "inputs/template.mph": template,
        }
        self._validate_job_inputs(job, logical_inputs)
        profile_data = {
            "project_yaml": "project/project.yaml",
            "scan_spec": f"project/{spec_relative.as_posix()}",
            "template": template_archive,
        }
        units = self._selected_units(job, work_unit_id)
        if content_addressed:
            validate_job_parameter_contract(job)
            records = [file_record(source, relative_path=name) for name, source in sorted(source_files.items())]
            for record in records:
                publish_asset(self.root, job, record, source_files[record.relative_path])
            publisher = OriginSpool(self.root, transfer_asset_cache=TransferAssetValidationCache(),
                                    storage_validator=self._storage_validator, volume_budget=self._volume_budget)
            return [publisher._publish(job, unit, runtime_version, profile_data, source_files,
                                       content_addressed=True, prepared_records=records)
                    for unit in units]
        return [
            self._publish(job, unit, runtime_version, profile_data, source_files, content_addressed=content_addressed)
            for unit in units
        ]

    def publish_project_worker(
        self,
        *,
        job: JobEnvelope,
        project_root: str | Path,
        runtime_version: str,
        work_unit_id: str | None = None,
        content_addressed: bool = False,
    ) -> list[Path]:
        if job.execution_profile_id != PROJECT_WORKER_V1.profile_id:
            raise ValueError("project-worker origin preparation requires project-worker-v1")
        root = Path(project_root).resolve()
        if not root.is_dir():
            raise FileNotFoundError(root)
        units = self._selected_units(job, work_unit_id)
        published = []
        for unit in units:
            payload = self._project_worker_payload(unit)
            source_files: dict[str, Path] = {}
            logical_inputs: dict[str, Path] = {}
            for relative_text in payload["project_files"]:
                relative = _relative_path(relative_text, "project file")
                source = (root / Path(*relative.parts)).resolve()
                source.relative_to(root)
                if not source.is_file():
                    raise FileNotFoundError(source)
                archive_path = f"project/{relative.as_posix()}"
                source_files[archive_path] = source
                logical_inputs[f"input/project/{relative.as_posix()}"] = source
            self._validate_job_inputs(job, logical_inputs)
            profile_data = {
                "entrypoint": payload["entrypoint"],
                "project_files": payload["project_files"],
            }
            published.append(self._publish(job, unit, runtime_version, profile_data, source_files, content_addressed=content_addressed))
        return published

    def validate(self, job: JobEnvelope, unit: WorkUnit) -> OriginBundleDescriptor:
        archive = self.outgoing_path(job, unit)
        if not archive.is_file():
            raise FileNotFoundError(f"sealed origin bundle is not ready: {archive}")
        return self._validate_archive(job, unit, archive)

    def _validate_archive(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        archive: Path,
    ) -> OriginBundleDescriptor:
        self._guard_storage()
        with zipfile.ZipFile(archive) as bundle:
            infos = self._validated_zip_infos(bundle)
            try:
                if infos["origin-request.json"].file_size > 1024 * 1024:
                    raise ValueError("origin bundle descriptor is too large")
                raw_descriptor = bundle.read("origin-request.json")
            except KeyError as exc:
                raise ValueError("origin bundle is missing origin-request.json") from exc
            if len(raw_descriptor) > 1024 * 1024:
                raise ValueError("origin bundle descriptor is too large")
            descriptor = OriginBundleDescriptor.model_validate_json(raw_descriptor)
            self._validate_descriptor(job, unit, descriptor)
            if ASSET_MARKER in infos:
                if (set(infos) != {"origin-request.json", ASSET_MARKER}
                    or infos[ASSET_MARKER].file_size != len(ASSET_MARKER_BYTES)
                    or bundle.read(ASSET_MARKER) != ASSET_MARKER_BYTES
                    or len(descriptor.files) > MAX_BUNDLE_FILES
                    or sum(r.size_bytes for r in descriptor.files) > MAX_BUNDLE_BYTES):
                    raise ValueError("invalid thin archive storage marker")
                self._validate_profile_contract(job, unit, descriptor)
                for record in descriptor.files:
                    portable_parts(record.relative_path)
                    verify_asset(self.root, job, record, transfer_cache=self._transfer_asset_cache)
                return descriptor
            file_infos = {name: info for name, info in infos.items() if name != "origin-request.json"}
            declared = {record.relative_path: record for record in descriptor.files}
            if set(file_infos) != set(declared):
                raise ValueError("origin bundle files do not exactly match the descriptor")
            for name, record in declared.items():
                info = file_infos[name]
                if info.file_size != record.size_bytes:
                    raise ValueError(f"origin bundle size mismatch: {name}")
                with bundle.open(info) as handle:
                    import hashlib

                    digest = hashlib.sha256()
                    while chunk := handle.read(1024 * 1024):
                        digest.update(chunk)
                if digest.hexdigest() != record.sha256:
                    raise ValueError(f"origin bundle hash mismatch: {name}")
            self._validate_profile_contract(job, unit, descriptor)
        return descriptor

    def reseal_runtime(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        runtime_version: str,
    ) -> dict[str, str]:
        """Rebind a validated, unstarted origin bundle to a reviewed runtime.

        Scientific inputs are copied byte-for-byte. The original archive is
        retained by SHA-256 before the descriptor-only replacement is made.
        """
        _safe_component(runtime_version, "runtime version")
        archive = self.outgoing_path(job, unit)
        descriptor = self.validate(job, unit)
        original_sha256 = sha256_file(archive)
        if descriptor.runtime_version == runtime_version:
            return {
                "path": str(archive),
                "previous_runtime_version": descriptor.runtime_version,
                "runtime_version": runtime_version,
                "previous_sha256": original_sha256,
                "sha256": original_sha256,
                "retained_path": "",
            }

        retained = (
            self.root
            / ".retained"
            / "runtime-migrations"
            / _safe_component(job.origin_submitter_id, "origin submitter ID")
            / _safe_component(job.job_id, "job ID")
            / _safe_component(unit.work_unit_id, "work-unit ID")
            / f"{_safe_component(descriptor.runtime_version, 'runtime version')}-{original_sha256}.zip"
        )
        managed_path(self.root, retained.relative_to(self.root).as_posix())
        retained_present = retained.exists()
        if retained_present:
            if not retained.is_file() or sha256_file(retained) != original_sha256:
                raise ValueError("retained origin bundle evidence conflicts with the current archive")
        promoted = descriptor.model_copy(update={"runtime_version": runtime_version})
        promoted.bundle_request_hash = sha256_value(promoted.hash_payload())
        promoted_json = json.dumps(promoted.model_dump(mode="json"), ensure_ascii=False, indent=2).encode("utf-8")
        with zipfile.ZipFile(archive) as source:
            source_infos = self._validated_zip_infos(source)
            replacement_bytes = sum(info.file_size for name, info in source_infos.items()
                                    if name != "origin-request.json") + len(promoted_json)
        # Only archive members are rewritten: a thin archive's asset descriptors
        # are not expanded here. Retained evidence already verified above need
        # not be copied again, but every replacement byte is always reserved.
        required = ((0 if retained_present else archive.stat().st_size) + replacement_bytes
                    + (replacement_bytes + 999) // 1000 + 64 * 1024 + 1024 * len(source_infos))
        claim = None
        if self._volume_budget is not None:
            try:
                claim = self._volume_budget.reserve(archive.parent, required,
                    holder_kind="origin_runtime_reseal", holder_key=f"{job.job_id}/{unit.work_unit_id}")
            except VolumeBudgetError as exc:
                error = PreLaunchSubmissionError("origin runtime reseal waits for the shared volume budget",
                    reason_code=exc.reason_code, error_type=type(exc).__name__)
                for field in ("required_bytes", "free_bytes", "reserved_bytes", "reserve_bytes"):
                    if hasattr(exc, field):
                        setattr(error, field, getattr(exc, field))
                raise error from exc
        owned_token = uuid.uuid4().hex
        retained_partial = retained.parent / (".origin-reseal-backup-" + owned_token + ".partial")
        replacement = archive.parent / (".origin-reseal-" + owned_token + ".zip")
        try:
            self._guard_storage()
            retained.parent.mkdir(parents=True, exist_ok=True)
            if not retained_present:
                shutil.copy2(archive, retained_partial)
                if sha256_file(retained_partial) != original_sha256:
                    raise ValueError("retained origin bundle evidence copy failed verification")
                self._guard_storage()
                try:
                    publish_new_file(retained_partial, retained)
                except FileExistsError:
                    if not retained.is_file() or sha256_file(retained) != original_sha256:
                        raise ValueError("retained origin bundle evidence conflicts with the current archive")
                retained_partial.unlink(missing_ok=True)
            self._guard_storage()
            with zipfile.ZipFile(archive, "r") as source, zipfile.ZipFile(
                replacement,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as target:
                infos = self._validated_zip_infos(source)
                for name, info in infos.items():
                    if name == "origin-request.json":
                        continue
                    with source.open(info) as input_handle, target.open(info, "w") as output_handle:
                        shutil.copyfileobj(input_handle, output_handle, length=1024 * 1024)
                target.writestr(
                    "origin-request.json",
                    promoted_json,
                )
            verified = self._validate_archive(job, unit, replacement)
            if verified.runtime_version != runtime_version:
                raise ValueError("replacement origin bundle runtime verification failed")
            replacement_sha256 = sha256_file(replacement)
            self._guard_storage()
            if sha256_file(archive) != original_sha256:
                raise ValueError("origin bundle changed while preparing its runtime replacement")
            os.replace(replacement, archive)
            final = self.validate(job, unit)
            if final.runtime_version != runtime_version or sha256_file(archive) != replacement_sha256:
                raise ValueError("promoted origin bundle failed post-replacement verification")
        finally:
            managed_path(self.root, retained_partial.relative_to(self.root).as_posix())
            managed_path(self.root, replacement.relative_to(self.root).as_posix())
            retained_partial.unlink(missing_ok=True)
            replacement.unlink(missing_ok=True)
            if claim is not None:
                self._volume_budget.release(claim, writer_stopped=True,
                    evidence="reseal archive readers/writers closed; exact owned backup/replacement staging cleaned")
        return {
            "path": str(archive),
            "previous_runtime_version": descriptor.runtime_version,
            "runtime_version": runtime_version,
            "previous_sha256": original_sha256,
            "sha256": replacement_sha256,
            "retained_path": str(retained),
        }

    def materialize_execution_bundle(
        self,
        *,
        job: JobEnvelope,
        assignment: Assignment,
        external_run_id: str,
        config: MachineExecutionConfig,
        runtime_version: str,
        output_zip: Path,
        cache_uploader: Callable[[Path, str], object] | None = None,
        bundle_storage_validator: Callable[[], Path] | None = None,
    ) -> Path:
        unit = next(item for item in job.work_units if item.work_unit_id == assignment.work_unit_id)
        descriptor = self.validate(job, unit)
        if descriptor.runtime_version != runtime_version:
            raise ValueError(
                "origin bundle runtime mismatch: "
                f"bundle={descriptor.runtime_version}; assignment={runtime_version}; "
                f"job={job.job_id}; work_unit={unit.work_unit_id}"
            )
        requested_output = Path(output_zip).absolute() if self._volume_budget is not None else Path(output_zip)
        try:
            with self._bundle_write(job, unit, assignment, descriptor, requested_output,
                                    external_run_id, runtime_version, bundle_storage_validator) as build_output:
                with self._extracted(job, unit) as extracted:
                    built = self._build_execution_bundle(job=job, unit=unit, assignment=assignment,
                        descriptor=descriptor, extracted=extracted, external_run_id=external_run_id,
                        config=config, runtime_version=runtime_version, output_zip=build_output,
                        cache_uploader=cache_uploader)
                if self._volume_budget is None:
                    return built
                self._guard_bundle_storage(requested_output, bundle_storage_validator)
                self.publish_or_reuse_execution_bundle(Path(built), requested_output)
                return requested_output
        except VolumeBudgetError as exc:
            error = PreLaunchSubmissionError("origin staging write waits for the shared volume budget",
                reason_code=exc.reason_code, error_type=type(exc).__name__)
            for field in ("required_bytes", "free_bytes", "reserved_bytes", "reserve_bytes"):
                if hasattr(exc, field):
                    setattr(error, field, getattr(exc, field))
            raise error from exc

    @staticmethod
    def publish_or_reuse_execution_bundle(built: Path, destination: Path) -> Path:
        """Publish without clobber, or reuse exactly identical sealed members.

        ZIP timestamps, member order and compression are not execution identity.
        A retry after proven prepublication failure may reuse the original ZIP
        only after every uncompressed member's actual size and SHA are read.
        """
        built, destination = Path(built), Path(destination)
        managed_path(built.parent, built.name)
        managed_path(destination.parent, destination.name)
        try:
            publish_new_file(built, destination)
            return destination
        except FileExistsError:
            pass

        def member_hash(bundle, info):
            actual_bytes, digest = 0, hashlib.sha256()
            with bundle.open(info) as source:
                while chunk := source.read(1024 * 1024):
                    actual_bytes += len(chunk)
                    digest.update(chunk)
            if actual_bytes != info.file_size:
                raise ValueError("sealed ZIP member size mismatch")
            return digest.digest()

        try:
            with zipfile.ZipFile(built) as rebuilt, zipfile.ZipFile(destination) as existing:
                rebuilt_infos, existing_infos = {}, {}
                for bundle, infos in ((rebuilt, rebuilt_infos), (existing, existing_infos)):
                    members = bundle.infolist()
                    if len(members) > MAX_BUNDLE_FILES + 8:
                        raise ValueError("sealed ZIP contains too many members")
                    seen = set()
                    for info in members:
                        portable_parts(info.filename)
                        folded = info.filename.casefold()
                        if (info.is_dir() or folded in seen or info.flag_bits & 1
                            or (info.external_attr >> 16) & 0o170000 == stat.S_IFLNK):
                            raise ValueError("sealed ZIP member identity is ambiguous")
                        seen.add(folded)
                        infos[info.filename] = info
                if rebuilt_infos.keys() != existing_infos.keys():
                    raise ValueError("sealed ZIP member inventory differs")
                for name, info in rebuilt_infos.items():
                    old = existing_infos[name]
                    if info.file_size != old.file_size or member_hash(rebuilt, info) != member_hash(existing, old):
                        raise ValueError("sealed ZIP member bytes differ")
            return destination
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
            raise PreLaunchSubmissionError("existing execution bundle differs; original sealed ZIP was preserved",
                reason_code="origin_bundle_publication_conflict") from exc

    @staticmethod
    def _guard_bundle_storage(output_zip, validator):
        output_zip = Path(output_zip).absolute()
        root = Path(validator()).absolute() if validator is not None else output_zip.parent
        try:
            relative = output_zip.relative_to(root)
        except ValueError as exc:
            raise PreLaunchSubmissionError("execution bundle is outside its registered role root",
                reason_code="storage_binding_changed") from exc
        managed_path(root, relative.as_posix())

    @staticmethod
    def _bundle_write_bound(job, unit, assignment, descriptor, external_run_id, runtime_version):
        # Project workers may copy all sealed inputs. Fixed COMSOL builders copy
        # only the project YAML and Scan Spec; the large MPH is read from the
        # separately reserved extraction and uploaded directly to worker cache.
        # Reserving that MPH again for staging and ZIP would triple its budget.
        # Include encoded selected-Unit metadata, filename/header expansion and
        # a known metadata margin. DEFLATE can expand incompressible data, so the
        # ZIP allowance adds 0.1% plus per-member headers and the final directory.
        staged_files = descriptor.files
        if job.execution_profile_id in _WORKBENCH_COMSOL_PROFILES:
            selected = {_relative_path(str(descriptor.profile_data[field]), field).as_posix()
                        for field in ("project_yaml", "scan_spec")}
            staged_files = [record for record in descriptor.files if record.relative_path in selected]
            if {record.relative_path for record in staged_files} != selected:
                raise ValueError("COMSOL bundle configuration is missing from the sealed inventory")
        inputs = sum(record.size_bytes for record in staged_files)
        attempt = next((item for item in unit.attempts if item.attempt_id == assignment.attempt_id), None)
        resolved = (attempt.resolved_resources if attempt is not None and attempt.resolved_resources is not None
                    else unit.resolved_resources)
        metadata = len(canonical_json_bytes({"payload": unit.payload,
            "resources": unit.resources.model_dump(mode="json"),
            "resolved_resources": resolved.model_dump(mode="json") if resolved else None,
            "assignment": assignment.model_dump(mode="json"), "job_id": job.job_id,
            "project_id": job.project_id, "external_run_id": external_run_id,
            "runtime_version": runtime_version}))
        names = sum(len(record.relative_path.encode("utf-8")) for record in staged_files)
        staged = inputs + 4 * metadata + 8 * names + BUNDLE_BUILD_METADATA_MARGIN_BYTES
        compressed = staged + (staged + 999) // 1000 + 64 * 1024 + 1024 * (len(staged_files) + 8)
        return staged + compressed

    @contextmanager
    def _bundle_write(self, job, unit, assignment, descriptor, output_zip,
                      external_run_id, runtime_version, validator):
        self._guard_bundle_storage(output_zip, validator)
        if self._volume_budget is None:
            yield output_zip
            return
        required = self._bundle_write_bound(job, unit, assignment, descriptor, external_run_id, runtime_version)
        holder = f"{job.job_id}/{unit.work_unit_id}/{assignment.attempt_id}/{external_run_id}"
        claim = self._volume_budget.reserve(output_zip.parent, required,
            holder_kind="dispatcher_bundle_build", holder_key=holder)
        owned_root = output_zip.parent / (".origin-build-" + uuid.uuid4().hex)
        build_output = owned_root / output_zip.name
        try:
            # No stage is created before both this and the extraction admission.
            # Existing caller ZIP/-files paths are never a builder's scratch.
            self._guard_bundle_storage(output_zip, validator)
            yield build_output
        finally:
            managed_path(output_zip.parent, owned_root.name)
            if owned_root.exists():
                shutil.rmtree(owned_root)
            self._volume_budget.release(claim, writer_stopped=True,
                evidence="synchronous builder returned/raised; unique ZIP and -files staging cleanup completed")

    @staticmethod
    def _build_execution_bundle(*, job, unit, assignment, descriptor, extracted,
                                external_run_id, config, runtime_version, output_zip, cache_uploader):
        if job.execution_profile_id == PROJECT_WORKER_V1.profile_id:
            payload = OriginSpool._project_worker_payload(unit)
            return build_project_worker_unit_bundle(
                project_root=extracted / "project",
                entrypoint=payload["entrypoint"],
                project_files=payload["project_files"],
                arguments=payload["arguments"],
                job=job,
                assignment=assignment,
                external_run_id=external_run_id,
                config=config,
                runtime_version=runtime_version,
                output_zip=output_zip,
            )
        if job.execution_profile_id in _WORKBENCH_COMSOL_PROFILES:
            project_yaml = extracted / Path(*_relative_path(
                str(descriptor.profile_data["project_yaml"]), "project_yaml"
            ).parts)
            scan_spec = extracted / Path(*_relative_path(
                str(descriptor.profile_data["scan_spec"]), "scan_spec"
            ).parts)
            template = extracted / Path(*_relative_path(
                str(descriptor.profile_data["template"]), "template"
            ).parts)
            template_hash = sha256_file(template)
            if cache_uploader is None:
                raise RuntimeError("COMSOL origin bundles require a controlled cache uploader")
            cache_uploader(template, template_hash)
            return build_comsol_unit_bundle(
                project_yaml=project_yaml,
                scan_spec=scan_spec,
                template_path=template,
                job=job,
                assignment=assignment,
                external_run_id=external_run_id,
                config=config,
                runtime_version=runtime_version,
                output_zip=output_zip,
            )
        raise ValueError(f"origin handoff does not support profile {job.execution_profile_id}")

    @staticmethod
    def _selected_units(job: JobEnvelope, work_unit_id: str | None) -> list[WorkUnit]:
        if work_unit_id is None:
            return list(job.work_units)
        units = [unit for unit in job.work_units if unit.work_unit_id == work_unit_id]
        if not units:
            raise KeyError(f"work unit is not present in Job envelope: {work_unit_id}")
        return units

    @staticmethod
    def _project_worker_payload(unit: WorkUnit) -> dict[str, Any]:
        payload = unit.payload
        allowed = {"kind", "entrypoint", "arguments", "project_files"}
        if set(payload) - allowed or payload.get("kind") != PROJECT_WORKER_V1.profile_id:
            raise ValueError("project-worker payload contains unsupported fields")
        entrypoint = _relative_path(str(payload.get("entrypoint", "")), "entrypoint").as_posix()
        arguments = payload.get("arguments", {})
        if not isinstance(arguments, dict):
            raise ValueError("project-worker arguments must be an object")
        raw_files = payload.get("project_files", [entrypoint])
        if not isinstance(raw_files, list) or not all(isinstance(item, str) for item in raw_files):
            raise ValueError("project-worker project_files must be a list of relative paths")
        project_files = sorted({_relative_path(item, "project file").as_posix() for item in raw_files} | {entrypoint})
        return {"entrypoint": entrypoint, "arguments": arguments, "project_files": project_files}

    @staticmethod
    def _workbench_base_payload(unit: WorkUnit) -> dict[str, Any]:
        if unit.payload.get("kind") == "workbench_comsol_scan_chunk":
            return unit.payload
        if unit.payload.get("kind") not in {
            "workbench_comsol_scan_items",
            "workbench_comsol_recipe_items",
        }:
            raise ValueError("Workbench unit has an unsupported payload kind")
        items = unit.payload.get("items")
        if not isinstance(items, list) or not items:
            raise ValueError("Workbench unit does not contain atomic items")
        payload = items[0].get("payload") if isinstance(items[0], dict) else None
        if not isinstance(payload, dict):
            raise ValueError("Workbench atomic item payload is invalid")
        return payload

    @staticmethod
    def _validate_job_inputs(job: JobEnvelope, sources: dict[str, Path]) -> None:
        expected = {record.relative_path: record for record in job.input_manifest}
        if set(expected) != set(sources):
            raise ValueError("origin source files do not exactly match Job input_manifest")
        for logical_path, source in sources.items():
            record = expected[logical_path]
            if source.stat().st_size != record.size_bytes or sha256_file(source) != record.sha256:
                raise ValueError(f"origin source does not match Job input_manifest: {logical_path}")

    def _publish(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        runtime_version: str,
        profile_data: dict[str, Any],
        source_files: dict[str, Path],
        *,
        content_addressed: bool = False,
        prepared_records: list[FileRecord] | None = None,
    ) -> Path:
        self._guard_storage()
        if prepared_records is None:
            validate_job_parameter_contract(job)
        raw_items = unit.payload.get("items", [])
        if isinstance(raw_items, list) and raw_items:
            validate_unit_parameter_contract(
                job,
                [item for item in raw_items if isinstance(item, dict)],
            )
        for value, label in (
            (job.origin_submitter_id, "origin submitter ID"),
            (job.project_id, "project ID"),
            (job.job_id, "job ID"),
            (unit.work_unit_id, "work-unit ID"),
            (runtime_version, "runtime version"),
        ):
            _safe_component(value, label)
        records = prepared_records if prepared_records is not None else [
            file_record(source, relative_path=archive_path)
            for archive_path, source in sorted(source_files.items())
        ]
        descriptor = OriginBundleDescriptor(
            origin_submitter_id=job.origin_submitter_id,
            project_id=job.project_id,
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
            profile_id=job.execution_profile_id,
            runtime_version=runtime_version,
            job_request_hash=job.request_hash,
            profile_data=profile_data,
            files=records,
            bundle_request_hash="0" * 64,
        )
        descriptor.bundle_request_hash = sha256_value(descriptor.hash_payload())
        destination = self.outgoing_path(job, unit)
        if content_addressed and destination.exists():
            current = self.validate(job, unit)
            with zipfile.ZipFile(destination) as existing:
                if ASSET_MARKER not in existing.namelist():
                    raise ValueError("existing legacy archive must be retained; thin publication cannot replace it")
            if current.hash_payload() != descriptor.hash_payload():
                raise ValueError("existing thin descriptor differs; use audited runtime migration if needed")
            return destination
        if content_addressed:
            self._validate_profile_contract(job, unit, descriptor)
            if prepared_records is None:
                for record in records:
                    publish_asset(self.root, job, record, source_files[record.relative_path])
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_suffix(destination.suffix + ".partial")
        partial.unlink(missing_ok=True)
        with zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            if content_addressed:
                bundle.writestr(ASSET_MARKER, ASSET_MARKER_BYTES)
            else:
                for archive_path, source in sorted(source_files.items()):
                    _relative_path(archive_path, "archive path")
                    bundle.write(source, archive_path)
            bundle.writestr(
                "origin-request.json",
                json.dumps(descriptor.model_dump(mode="json"), ensure_ascii=False, indent=2),
            )
        os.replace(partial, destination)
        self.validate(job, unit)
        return destination

    @staticmethod
    def _validated_zip_infos(bundle: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
        infos: dict[str, zipfile.ZipInfo] = {}
        members = bundle.infolist()
        if len(members) > MAX_BUNDLE_FILES:
            raise ValueError("origin bundle contains too many files")
        seen: set[str] = set()
        total = 0
        for info in members:
            if info.is_dir():
                raise ValueError("origin bundle must not contain explicit directory entries")
            path = _relative_path(info.filename, "ZIP member")
            name = path.as_posix()
            portable_parts(info.filename)
            folded = name.casefold()
            if folded in seen:
                raise ValueError(f"origin bundle contains duplicate ZIP member: {name}")
            seen.add(folded)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError(f"origin bundle contains a symbolic link: {name}")
            if info.flag_bits & 0x1:
                raise ValueError("encrypted origin bundles are not supported")
            total += info.file_size
            if total > MAX_BUNDLE_BYTES:
                raise ValueError("origin bundle exceeds the uncompressed size limit")
            infos[name] = info
        if len(infos) > MAX_BUNDLE_FILES:
            raise ValueError("origin bundle contains too many files")
        return infos

    @staticmethod
    def _validate_descriptor(
        job: JobEnvelope,
        unit: WorkUnit,
        descriptor: OriginBundleDescriptor,
    ) -> None:
        expected = {
            "origin_submitter_id": job.origin_submitter_id,
            "project_id": job.project_id,
            "job_id": job.job_id,
            "work_unit_id": unit.work_unit_id,
            "profile_id": job.execution_profile_id,
            "job_request_hash": job.request_hash,
        }
        for field, value in expected.items():
            if getattr(descriptor, field) != value:
                raise ValueError(f"origin bundle {field} does not match the scheduled Job")
        expected_hash = sha256_value(descriptor.hash_payload())
        if descriptor.bundle_request_hash != expected_hash:
            raise ValueError("origin bundle request hash is invalid")

    @staticmethod
    def _validate_profile_contract(
        job: JobEnvelope,
        unit: WorkUnit,
        descriptor: OriginBundleDescriptor,
    ) -> None:
        records = {record.relative_path: record for record in descriptor.files}

        def compare(logical_path: str, archive_path: str) -> None:
            expected = next(
                (record for record in job.input_manifest if record.relative_path == logical_path),
                None,
            )
            actual = records.get(archive_path)
            if expected is None or actual is None:
                raise ValueError(f"origin bundle input mapping is incomplete: {logical_path}")
            if (expected.size_bytes, expected.sha256) != (actual.size_bytes, actual.sha256):
                raise ValueError(f"origin bundle input hash does not match Job: {logical_path}")

        if job.execution_profile_id == PROJECT_WORKER_V1.profile_id:
            payload = OriginSpool._project_worker_payload(unit)
            if descriptor.profile_data.get("entrypoint") != payload["entrypoint"]:
                raise ValueError("origin project-worker entrypoint does not match the Job")
            if descriptor.profile_data.get("project_files") != payload["project_files"]:
                raise ValueError("origin project-worker file list does not match the Job")
            expected_archives = {f"project/{relative}" for relative in payload["project_files"]}
            if set(records) != expected_archives:
                raise ValueError("origin project-worker files do not match the Job payload")
            for relative in payload["project_files"]:
                compare(f"input/project/{relative}", f"project/{relative}")
            return

        if job.execution_profile_id in _WORKBENCH_COMSOL_PROFILES:
            paths = descriptor.profile_data
            try:
                project_yaml = _relative_path(str(paths["project_yaml"]), "project_yaml").as_posix()
                scan_spec = _relative_path(str(paths["scan_spec"]), "scan_spec").as_posix()
                template = _relative_path(str(paths["template"]), "template").as_posix()
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("origin Workbench profile paths are invalid") from exc
            for path in (project_yaml, scan_spec, template):
                if path not in records:
                    raise ValueError(f"origin Workbench source is not declared: {path}")
            compare("inputs/project.yaml", project_yaml)
            spec_name = (
                PurePosixPath(scan_spec).name
                if job.execution_profile_id in {
                    WORKBENCH_COMSOL_TEMPLATE_BUILD_V1.profile_id,
                    WORKBENCH_COMSOL_SAVED_READOUT_V1.profile_id,
                }
                else Path(str(OriginSpool._workbench_base_payload(unit).get("scan_spec", "scan.yaml"))).name
            )
            compare(f"inputs/{spec_name}", scan_spec)
            compare("inputs/template.mph", template)
            return

        raise ValueError(f"origin handoff does not support profile {job.execution_profile_id}")

    @contextmanager
    def _extracted(self, job: JobEnvelope, unit: WorkUnit) -> Iterator[Path]:
        archive = self.outgoing_path(job, unit)
        work_root = self.root / ".work"
        destination = work_root / uuid.uuid4().hex
        claim = None
        try:
            with zipfile.ZipFile(archive) as bundle:
                infos = self._validated_zip_infos(bundle)
                descriptor = self.validate(job, unit) if ASSET_MARKER in infos else None
                required = (sum(record.size_bytes for record in descriptor.files) if descriptor is not None
                            else sum(info.file_size for info in infos.values()))
                if self._volume_budget is not None:
                    claim = self._volume_budget.reserve(work_root, max(1, required),
                        holder_kind="origin_extract", holder_key=f"{job.job_id}/{unit.work_unit_id}/{destination.name}")
                self._guard_storage()
                work_root.mkdir(parents=True, exist_ok=True)
                destination.mkdir()
                if ASSET_MARKER in infos:
                    for record in descriptor.files:
                        target = destination.joinpath(*portable_parts(record.relative_path))
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(verify_asset(self.root, job, record), target)
                    yield destination
                    return
                for name, info in infos.items():
                    target = (destination / Path(*PurePosixPath(name).parts)).resolve()
                    target.relative_to(destination)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.open(info) as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
            yield destination
        finally:
            if self._volume_budget is None:
                shutil.rmtree(destination, ignore_errors=True)
            else:
                managed_path(work_root, destination.name)
                if destination.exists():
                    shutil.rmtree(destination)
                if claim is not None:
                    self._volume_budget.release(claim, writer_stopped=True,
                        evidence="extraction readers/writers closed; unique .work directory cleanup completed")


def build_project_worker_job(
    *,
    project_root: str | Path,
    entrypoint: str,
    project_files: list[str],
    arguments: dict[str, Any],
    origin_submitter_id: str,
    user_id: str,
    project_id: str,
    expected_duration_s: int = 600,
    priority: int | None = None,
    resources: ResourceRequest | None = None,
) -> JobEnvelope:
    """Build a metadata envelope whose input hashes bind a project-worker bundle."""
    root = Path(project_root).resolve()
    entry = _relative_path(entrypoint, "entrypoint").as_posix()
    selected = sorted({_relative_path(item, "project file").as_posix() for item in project_files} | {entry})
    records = []
    for relative_text in selected:
        source = (root / Path(*PurePosixPath(relative_text).parts)).resolve()
        source.relative_to(root)
        if not source.is_file():
            raise FileNotFoundError(source)
        records.append(file_record(source, relative_path=f"input/project/{relative_text}"))
    payload = {
        "kind": PROJECT_WORKER_V1.profile_id,
        "entrypoint": entry,
        "arguments": arguments,
        "project_files": selected,
    }
    request_hash = sha256_value({
        "origin_submitter_id": origin_submitter_id,
        "user_id": user_id,
        "project_id": project_id,
        "profile_id": PROJECT_WORKER_V1.profile_id,
        "payload": payload,
        "input_manifest": [record.model_dump(mode="json") for record in records],
        "priority": priority,
    })
    unit = WorkUnit(
        work_unit_id=f"unit-{request_hash[:16]}-0000",
        ordinal=0,
        payload=payload,
        expected_duration_s=expected_duration_s,
        resources=resources or PROJECT_WORKER_V1.default_resources,
        required_capabilities=set(PROJECT_WORKER_V1.required_capabilities),
    )
    return JobEnvelope(
        origin_submitter_id=origin_submitter_id,
        user_id=user_id,
        project_id=project_id,
        execution_profile_id=PROJECT_WORKER_V1.profile_id,
        request_hash=request_hash,
        input_manifest=records,
        work_units=[unit],
        priority=priority if priority is not None else 0,
        priority_explicit=priority is not None,
    )
