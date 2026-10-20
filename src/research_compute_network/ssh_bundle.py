"""Versioned runtime and sealed COMSOL work-unit bundle builders."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path, PurePosixPath

import yaml

from .hashing import sha256_file, sha256_value
from .models import Assignment, JobEnvelope, MachineExecutionConfig
from .parameter_guard import validate_job_parameter_contract, validate_unit_parameter_contract
from .remote_agent.comsol_recipe_contracts import (
    FIXED_COMSOL_RECIPE_CONTRACTS,
    validate_fixed_recipe_items,
)
from .remote_agent.template_build_contracts import TEMPLATE_BUILD_PRESETS
from .remote_agent.saved_readout_contracts import (
    SAVED_READOUT_DIAGNOSTIC, SAVED_READOUT_DIAGNOSTICS,
    PX1050_SAVED_READOUT_DIAGNOSTIC, SAVED_READOUT_RECIPE_KIND,
)
from .remote_storage import RemoteLayout


SAFE_FAKE_PROFILE_ID = "rcn-safe-fake-v1"
SAFE_FAKE_DURATION_SECONDS = 3.0
PROJECT_WORKER_PROFILE_ID = "project-worker-v1"
WORKBENCH_COMSOL_SCAN_PROFILE_ID = "workbench-comsol-scan-v1"
WORKBENCH_COMSOL_EIGEN_PROFILE_ID = "workbench-comsol-eigen-v2"
WORKBENCH_COMSOL_FREQUENCY_PROFILE_ID = "workbench-comsol-frequency-v1"
WORKBENCH_COMSOL_RECIPE_PROFILES = {
    profile_id: contract.recipe_kind
    for profile_id, contract in FIXED_COMSOL_RECIPE_CONTRACTS.items()
}


def _resolved_resource_payload(unit, attempt_id: str | None) -> dict:
    attempt = next(
        (item for item in unit.attempts if item.attempt_id == attempt_id),
        None,
    )
    resolved = (
        attempt.resolved_resources
        if attempt is not None and attempt.resolved_resources is not None
        else unit.resolved_resources
    )
    if resolved is not None:
        return resolved.model_dump(mode="json")
    return {
        "schema_version": 1,
        "resources": unit.resources.model_dump(mode="json"),
        "source": "origin_legacy",
        "policy_revision": 1,
        "evidence_sample_count": 0,
        "memory_safety_margin_mb": 0,
        "disk_safety_margin_mb": 0,
    }


def _dispatch_payload(assignment: Assignment) -> dict:
    return {
        "dispatch_state": "prepared" if assignment.prepared else "queued",
        "dispatch_reservation_id": assignment.dispatch_reservation_id,
    }


def _immutable_unit_identity(unit) -> dict:
    """Return only submission facts that must survive dispatch transitions."""
    return {
        "schema_version": unit.schema_version,
        "work_unit_id": unit.work_unit_id,
        "ordinal": unit.ordinal,
        "payload": unit.payload,
        "atomic_item_ids": unit.atomic_item_ids,
        "expected_duration_s": unit.expected_duration_s,
        "resources": unit.resources.model_dump(mode="json"),
        "required_capabilities": sorted(unit.required_capabilities),
        "allowed_solver_variants": sorted(
            variant.value for variant in unit.allowed_solver_variants
        ),
        "solver_policy": unit.solver_policy.value,
        "resource_mode": unit.resource_mode.value,
        "solver_approval_id": unit.solver_approval_id,
    }


def _numeric(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _mapping_file(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"structured input must be a mapping: {path}")
    return value


def _fixed_values(section: object) -> dict:
    if not isinstance(section, dict):
        return {}
    result = {}
    for key, value in section.items():
        if key in {"mode", "combinations", "description"}:
            continue
        if isinstance(value, list) and len(value) == 1:
            result[key] = value[0]
        elif not isinstance(value, (list, dict)):
            result[key] = value
    return result


def _copy_selected_tree(source: Path, destination: Path) -> None:
    # ``research_agent_workbench.data`` is executable package code, not a
    # research-project dataset directory, and must be included.
    ignored = {"__pycache__", ".pytest_cache", ".git"}
    for path in source.rglob("*"):
        relative = path.relative_to(source)
        if any(part in ignored for part in relative.parts):
            continue
        target = destination / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.suffix not in {".pyc", ".pyo"}:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def build_runtime_package(
    *,
    workbench_source: Path,
    remote_agent_source: Path,
    output_root: Path,
    template_build_presets: dict[str, tuple[Path, str]] | None = None,
    saved_readout_diagnostics: dict[str, tuple[Path, str]] | None = None,
) -> tuple[str, Path]:
    """Create a reviewed source snapshot without installing on a worker.

    ``template_build_presets`` is a local release-time input, never accepted
    from a Job. It freezes only the registered project-owned scientific
    source into its fixed module slot. Without it, historical package layout
    and runtime fingerprints retain their exact behavior.
    ``saved_readout_diagnostics`` independently freezes registered
    saved-solution primitives in its fixed slot; it is never a Job input.
    """
    workbench_source = Path(workbench_source).resolve()
    remote_agent_source = Path(remote_agent_source).resolve()
    if not workbench_source.is_dir() or not remote_agent_source.is_dir():
        raise FileNotFoundError("runtime source roots must be existing directories")
    files = [
        path
        for root in (workbench_source, remote_agent_source)
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts
    ]
    fingerprint = {
        (
            f"workbench/{path.relative_to(workbench_source).as_posix()}"
            if path.is_relative_to(workbench_source)
            else f"remote-agent/{path.relative_to(remote_agent_source).as_posix()}"
        ): sha256_file(path)
        for path in sorted(files)
    }
    frozen_presets: dict[str, bytes] = {}
    if template_build_presets is not None:
        if (not isinstance(template_build_presets, dict) or not template_build_presets
                or any(type(preset) is not str or preset not in TEMPLATE_BUILD_PRESETS
                       for preset in template_build_presets)):
            raise ValueError("runtime release accepts only the reviewed nonempty template construction preset subset")
        for preset, declared in sorted(template_build_presets.items()):
            if not isinstance(declared, tuple) or len(declared) != 2:
                raise ValueError("template construction release requires source and SHA-256")
            source, expected_sha256 = declared
            if not isinstance(source, (str, Path)):
                raise ValueError("template construction release source must be a Python file path")
            source = Path(source).resolve()
            if not source.is_file() or source.suffix != ".py":
                raise ValueError("template construction release source must be a Python file")
            if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
                raise ValueError("template construction release source hash is invalid")
            content = source.read_bytes()
            actual_sha256 = hashlib.sha256(content).hexdigest()
            if actual_sha256 != expected_sha256:
                raise ValueError("template construction release source changed after review")
            module_relative = f"runtime/presets/{preset}.py"
            if (workbench_source / module_relative).exists():
                raise ValueError("project-owned construction source must not have a second Workbench source copy")
            frozen_presets[module_relative] = content
            fingerprint[f"workbench/{module_relative}"] = actual_sha256
        init_relative = "runtime/presets/__init__.py"
        if not (workbench_source / init_relative).is_file():
            frozen_presets[init_relative] = b'"""Registered, release-frozen project construction presets."""\n'
            fingerprint[f"workbench/{init_relative}"] = hashlib.sha256(frozen_presets[init_relative]).hexdigest()
    frozen_readouts: dict[str, bytes] = {}
    if saved_readout_diagnostics is not None:
        if (not isinstance(saved_readout_diagnostics, dict) or not saved_readout_diagnostics
                or any(type(name) is not str or name not in SAVED_READOUT_DIAGNOSTICS
                       for name in saved_readout_diagnostics)):
            raise ValueError("runtime release accepts only registered saved readout diagnostics")
        if (PX1050_SAVED_READOUT_DIAGNOSTIC in saved_readout_diagnostics
                and SAVED_READOUT_DIAGNOSTIC not in saved_readout_diagnostics):
            raise ValueError("Px1050 saved readout requires its frozen Circle helper dependency")
        for diagnostic, declared in sorted(saved_readout_diagnostics.items()):
            if not isinstance(declared, tuple) or len(declared) != 2:
                raise ValueError("saved readout release requires source and SHA-256")
            source, expected_sha256 = declared
            if not isinstance(source, (str, Path)):
                raise ValueError("saved readout release source must be a Python file path")
            source = Path(source).resolve()
            if not source.is_file() or source.suffix != ".py":
                raise ValueError("saved readout release source must be a Python file")
            if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
                raise ValueError("saved readout release source hash is invalid")
            content = source.read_bytes()
            actual_sha256 = hashlib.sha256(content).hexdigest()
            if actual_sha256 != expected_sha256:
                raise ValueError("saved readout release source changed after review")
            module_relative = f"runtime/presets/{diagnostic}.py"
            if (workbench_source / module_relative).exists():
                raise ValueError("project-owned saved readout source must not have a second Workbench source copy")
            frozen_readouts[module_relative] = content
            fingerprint[f"workbench/{module_relative}"] = actual_sha256
        init_relative = "runtime/presets/__init__.py"
        if not (workbench_source / init_relative).is_file() and init_relative not in frozen_presets:
            frozen_readouts[init_relative] = b'"""Registered, release-frozen project saved readouts."""\n'
            fingerprint[f"workbench/{init_relative}"] = hashlib.sha256(frozen_readouts[init_relative]).hexdigest()
    fingerprint["__runtime_layout_version__"] = "2"
    version = sha256_value(fingerprint)[:24]
    package_root = output_root / version
    archive = output_root / f"runtime-{version}.zip"
    if archive.is_file():
        return version, archive
    if package_root.exists():
        shutil.rmtree(package_root)
    package_root.mkdir(parents=True)
    _copy_selected_tree(workbench_source, package_root / "workbench-src" / "research_agent_workbench")
    _copy_selected_tree(remote_agent_source, package_root / "remote-agent")
    for relative, content in (frozen_presets | frozen_readouts).items():
        destination = package_root / "workbench-src" / "research_agent_workbench" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    manifest = {"schema_version": 1, "version": version, "files": fingerprint}
    if template_build_presets is not None:
        manifest["template_build_presets"] = {
            preset: fingerprint[f"workbench/runtime/presets/{preset}.py"]
            for preset in sorted(template_build_presets)
        }
    if saved_readout_diagnostics is not None:
        manifest["saved_readout_diagnostics"] = {
            diagnostic: fingerprint[f"workbench/runtime/presets/{diagnostic}.py"]
            for diagnostic in sorted(saved_readout_diagnostics)
        }
    (package_root / "runtime-manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    output_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(package_root.rglob("*")):
            if path.is_file():
                info = zipfile.ZipInfo(
                    path.relative_to(package_root).as_posix(),
                    date_time=(1980, 1, 1, 0, 0, 0),
                )
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (0o100644 & 0xFFFF) << 16
                bundle.writestr(info, path.read_bytes())
    shutil.rmtree(package_root)
    return version, archive


def _build_legacy_comsol_unit_bundle(
    *,
    project_yaml: Path,
    scan_spec: Path,
    template_path: Path | None = None,
    job: JobEnvelope,
    assignment: Assignment,
    external_run_id: str,
    config: MachineExecutionConfig,
    runtime_version: str,
    output_zip: Path,
) -> Path:
    project = _mapping_file(project_yaml)
    spec_document = _mapping_file(scan_spec)
    spec = spec_document.get("scan", spec_document)
    if not isinstance(spec, dict):
        raise ValueError("COMSOL Scan Spec must contain a mapping")
    unit = next(unit for unit in job.work_units if unit.work_unit_id == assignment.work_unit_id)
    payload_kind = unit.payload.get("kind")
    if payload_kind == "workbench_comsol_scan_chunk":
        point_payloads = [unit.payload]
        m1_values = [float(value) for value in unit.payload["m1"]]
        m2_values = [float(value) for value in unit.payload["m2"]]
        k_indices = [int(value) for value in unit.payload.get(
            "k_indices",
            range(int(unit.payload["chunk_start"]), int(unit.payload["chunk_start"]) + len(m1_values)),
        )]
    elif payload_kind == "workbench_comsol_scan_items":
        raw_items = unit.payload.get("items")
        if not isinstance(raw_items, list) or not raw_items:
            raise ValueError("partitioned Workbench unit requires atomic items")
        point_payloads = []
        for item in raw_items:
            payload = item.get("payload") if isinstance(item, dict) else None
            if not isinstance(payload, dict):
                raise ValueError("partitioned Workbench item payload must be a mapping")
            point_payloads.append(payload)
        m1_values = [float(point["m1"]) for point in point_payloads]
        m2_values = [float(point["m2"]) for point in point_payloads]
        k_indices = [int(point["k_idx"]) for point in point_payloads]
    else:
        raise ValueError("SSH COMSOL profile only accepts Workbench scan chunks or atomic items")
    base_payload = point_payloads[0]
    template = Path(template_path).resolve() if template_path is not None else None
    if template is None or not template.is_file():
        raise FileNotFoundError("COMSOL template is unavailable")
    template_hash = sha256_file(template)
    layout = RemoteLayout.from_string(config.remote_root)
    run_dir = layout.active_run(job.project_id, job.job_id, unit.work_unit_id)
    remote_template = layout.root / "cache" / "objects" / template_hash / Path(template).name
    output_dir = run_dir / "output"

    overrides = {}
    overrides.update(_fixed_values(spec.get("param")))
    overrides.update(_fixed_values(spec.get("param1")))
    overrides.update(_fixed_values(spec.get("param3")))
    p3 = _fixed_values(spec.get("param3"))
    execution = base_payload.get("execution", {})
    if execution and not isinstance(execution, dict):
        raise ValueError("COMSOL execution payload must be a mapping")
    comsol = project.get("comsol", {}) if isinstance(project.get("comsol"), dict) else {}
    job_payload = {
        "template_path": str(remote_template),
        "comsol_version": config.comsol_version,
        "mesh_tag": execution.get("mesh_tag", comsol.get("mesh_tag", "mesh1")),
        "m1": m1_values,
        "m2": m2_values,
        "k_indices": k_indices,
        "chunk_start": k_indices[0],
        "chunk_index": int(unit.ordinal),
        "neigs": int(execution.get("neigs", spec.get("neigs"))),
        "shift": execution.get("shift", spec.get("shift")),
        "mesh": execution.get("mesh", spec.get("mesh")),
        "grid_shape": base_payload.get("grid_shape"),
        "path_label": execution.get("path_label", spec.get("path_label")),
        "run_id": job.job_id,
        "fill": _numeric(p3.get("fill")),
        "P_override": _numeric(p3.get("P")),
        "fill_override": _numeric(p3.get("fill")),
        "t_tot_override": _numeric(p3.get("t_tot")),
        "asym_1": _numeric(p3.get("arrow_asym_factor")),
        "asym_2": _numeric(p3.get("trap_asym_factor")),
        "asym_3": _numeric(p3.get("paral_asym_factor")),
        "param_overrides": overrides,
        "solver_variant": assignment.solver_variant.value,
        "solver_policy": job.solver_policy.value,
        "resource_mode": job.resource_mode.value,
        "progress_path": str(run_dir / "progress.json"),
        "out_csv": str(output_dir / f"chunk_{unit.ordinal:03d}.csv"),
        "out_manifest": str(output_dir / f"chunk_{unit.ordinal:03d}_manifest.json"),
    }
    request_hash = sha256_value({
        "job_request_hash": job.request_hash,
        "unit": _immutable_unit_identity(unit),
        "runtime_version": runtime_version,
        "template_sha256": template_hash,
        "solver_variant": assignment.solver_variant.value,
        "solver_approval_id": assignment.solver_approval_id or job.solver_approval_id,
        "solver_compatibility_fingerprint": (
            assignment.solver_compatibility_fingerprint
            or job.solver_compatibility_fingerprint
        ),
    })
    staging = output_zip.parent / (output_zip.stem + "-files")
    if staging.exists():
        shutil.rmtree(staging)
    (staging / "input").mkdir(parents=True)
    (staging / "input" / "job.json").write_text(json.dumps(job_payload, indent=2), encoding="utf-8")
    shutil.copy2(project_yaml, staging / "input" / "project.yaml")
    shutil.copy2(scan_spec, staging / "input" / scan_spec.name)
    records = []
    for path in sorted((staging / "input").rglob("*")):
        if path.is_file():
            records.append({
                "path": path.relative_to(staging).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            })
    request = {
        **_dispatch_payload(assignment),
        "schema_version": 1,
        "external_run_id": external_run_id,
        "machine_id": config.machine_id,
        "project_id": job.project_id,
        "job_id": job.job_id,
        "work_unit_id": unit.work_unit_id,
        "request_hash": request_hash,
        "profile_id": job.execution_profile_id,
        "runtime_version": runtime_version,
        "template_sha256": template_hash,
        "solver_variant": assignment.solver_variant.value,
        "solver_policy": job.solver_policy.value,
        "resource_mode": job.resource_mode.value,
        "solver_approval_id": (
            job.solver_approval_id
            if assignment.solver_variant.value == "cudss"
            or job.execution_profile_id in {"workbench-comsol-study-v1", "workbench-comsol-study-v2"}
            else None
        ),
        "resolved_resources": _resolved_resource_payload(unit, assignment.attempt_id),
        "files": records,
    }
    (staging / "request.json").write_text(json.dumps(request, indent=2), encoding="utf-8")
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(staging).as_posix())
    shutil.rmtree(staging)
    return output_zip


def _recipe_items(job: JobEnvelope, assignment: Assignment) -> tuple[object, list[dict]]:
    validate_job_parameter_contract(job)
    unit = next(unit for unit in job.work_units if unit.work_unit_id == assignment.work_unit_id)
    expected_recipe = WORKBENCH_COMSOL_RECIPE_PROFILES.get(job.execution_profile_id)
    if expected_recipe is None or job.recipe_kind != expected_recipe:
        raise ValueError("COMSOL recipe does not match the fixed execution profile")
    if unit.payload.get("kind") != "workbench_comsol_recipe_items":
        raise ValueError("COMSOL recipe profile accepts only compiled atomic items")
    raw_items = unit.payload.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError("COMSOL recipe WorkUnit requires atomic items")
    setups: set[str] = set()
    normalized: list[dict] = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            raise ValueError("COMSOL atomic item must be an object")
        item_id = raw.get("item_id")
        ordinal = raw.get("ordinal")
        setup = raw.get("setup_fingerprint")
        payload = raw.get("payload")
        coordinates = raw.get("coordinates")
        if not isinstance(item_id, str) or not item_id:
            raise ValueError("COMSOL atomic item has no stable ID")
        if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 0:
            raise ValueError("COMSOL atomic item has an invalid ordinal")
        if not isinstance(setup, str) or len(setup) != 64:
            raise ValueError("COMSOL atomic item has no setup fingerprint")
        if not isinstance(payload, dict) or not isinstance(coordinates, dict):
            raise ValueError("COMSOL atomic item payload and coordinates must be objects")
        # Generic Study atoms deliberately carry a declarative Study descriptor
        # instead of duplicating the outer recipe name. The strict generic
        # contract validates their kind and complete allowlisted payload below.
        if expected_recipe not in {"comsol_study", "comsol_template_build", SAVED_READOUT_RECIPE_KIND} and payload.get("recipe_kind") != expected_recipe:
            raise ValueError("COMSOL atomic item recipe does not match the Job")
        setups.add(setup)
        normalized.append({
            "item_id": item_id,
            "ordinal": ordinal,
            "setup_fingerprint": setup,
            "coordinates": coordinates,
            "payload": payload,
        })
    if len(setups) != 1:
        raise ValueError("one COMSOL WorkUnit cannot mix setup fingerprints")
    if [item["ordinal"] for item in normalized] != sorted(item["ordinal"] for item in normalized):
        raise ValueError("COMSOL atomic items must retain source ordinal order")
    validate_fixed_recipe_items(
        profile_id=job.execution_profile_id,
        recipe_kind=job.recipe_kind,
        solver_variant=assignment.solver_variant.value,
        items=normalized,
    )
    validate_unit_parameter_contract(job, normalized)
    return unit, normalized


def _build_recipe_comsol_unit_bundle(
    *,
    project_yaml: Path,
    scan_spec: Path,
    template_path: Path | None,
    job: JobEnvelope,
    assignment: Assignment,
    external_run_id: str,
    config: MachineExecutionConfig,
    runtime_version: str,
    output_zip: Path,
) -> Path:
    unit, items = _recipe_items(job, assignment)
    if assignment.runtime_version and assignment.runtime_version != runtime_version:
        raise ValueError("assignment runtime does not match the bundle runtime")
    template = Path(template_path).resolve() if template_path is not None else None
    if template is None or not template.is_file():
        raise FileNotFoundError("COMSOL template is unavailable")
    template_hash = sha256_file(template)
    if job.template_sha256 and template_hash != job.template_sha256:
        raise ValueError("COMSOL template changed after partition confirmation")
    if any(
        item.get("payload", {}).get("template_sha256") not in {None, template_hash}
        for item in items
    ):
        raise ValueError("COMSOL atomic item template hash does not match the sealed template")
    layout = RemoteLayout.from_string(config.remote_root)
    run_dir = layout.active_run(job.project_id, job.job_id, unit.work_unit_id)
    remote_template = layout.root / "cache" / "objects" / template_hash / template.name
    output_dir = run_dir / "output"
    estimated_unit_output_bytes = None
    if job.estimated_output_bytes is not None:
        total_items = max(1, int(job.atomic_item_count or len(items)))
        estimated_unit_output_bytes = (
            int(job.estimated_output_bytes) * len(items) + total_items - 1
        ) // total_items
    job_payload = {
        "schema_version": 2,
        "profile_id": job.execution_profile_id,
        # This is issued by the dispatcher for the concrete launch, rather
        # than inferred from a WorkUnit after collection.
        "attempt_id": assignment.attempt_id,
        "machine_id": assignment.machine_id,
        "runtime_version": runtime_version,
        "recipe_kind": job.recipe_kind,
        "campaign_id": job.campaign_id,
        "campaign_task_id": job.campaign_task_id,
        "source_spec_sha256": job.source_spec_sha256,
        "study_kind": job.study_kind.value if job.study_kind else None,
        "template_role": job.template_role,
        "template_sha256": job.template_sha256,
        "output_contract_sha256": job.output_contract_sha256,
        "estimated_output_bytes": estimated_unit_output_bytes,
        "estimated_job_output_bytes": job.estimated_output_bytes,
        "template_path": str(remote_template),
        "comsol_version": config.comsol_version,
        "solver_variant": assignment.solver_variant.value,
        "solver_policy": job.solver_policy.value,
        "resource_mode": job.resource_mode.value,
        "solver_approval_id": assignment.solver_approval_id or job.solver_approval_id,
        "solver_compatibility_fingerprint": (
            assignment.solver_compatibility_fingerprint
            or job.solver_compatibility_fingerprint
        ),
        "resolved_resources": _resolved_resource_payload(unit, assignment.attempt_id),
        "items": items,
        "progress_path": str(run_dir / "progress.json"),
        "output_path": str(output_dir / f"unit_{unit.ordinal:04d}_results.json"),
    }
    request_hash = sha256_value({
        "job_request_hash": job.request_hash,
        "unit": _immutable_unit_identity(unit),
        "runtime_version": runtime_version,
        "template_sha256": template_hash,
        "recipe_kind": job.recipe_kind,
        "solver_variant": assignment.solver_variant.value,
        "solver_approval_id": assignment.solver_approval_id or job.solver_approval_id,
        "solver_compatibility_fingerprint": (
            assignment.solver_compatibility_fingerprint
            or job.solver_compatibility_fingerprint
        ),
    })
    staging = output_zip.parent / (output_zip.stem + "-files")
    if staging.exists():
        shutil.rmtree(staging)
    input_dir = staging / "input"
    input_dir.mkdir(parents=True)
    (input_dir / "job.json").write_text(
        json.dumps(job_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    shutil.copy2(project_yaml, input_dir / "project.yaml")
    shutil.copy2(scan_spec, input_dir / scan_spec.name)
    records = []
    for path in sorted(input_dir.rglob("*")):
        if path.is_file():
            records.append({
                "path": path.relative_to(staging).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            })
    request = {
        **_dispatch_payload(assignment),
        "schema_version": 1,
        "external_run_id": external_run_id,
        "machine_id": config.machine_id,
        "project_id": job.project_id,
        "job_id": job.job_id,
        "work_unit_id": unit.work_unit_id,
        "attempt_id": assignment.attempt_id,
        "request_hash": request_hash,
        "profile_id": job.execution_profile_id,
        "runtime_version": runtime_version,
        "template_sha256": template_hash,
        "solver_variant": assignment.solver_variant.value,
        "solver_policy": job.solver_policy.value,
        "resource_mode": job.resource_mode.value,
        "solver_approval_id": job_payload["solver_approval_id"],
        "resolved_resources": job_payload["resolved_resources"],
        "files": records,
    }
    (staging / "request.json").write_text(json.dumps(request, indent=2), encoding="utf-8")
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(staging).as_posix())
    shutil.rmtree(staging)
    return output_zip


def build_comsol_unit_bundle(**kwargs) -> Path:
    """Build either the legacy v1 scan bundle or a fixed v2 recipe bundle."""
    job = kwargs.get("job")
    if not isinstance(job, JobEnvelope):
        raise TypeError("job must be a JobEnvelope")
    if job.execution_profile_id == WORKBENCH_COMSOL_SCAN_PROFILE_ID:
        return _build_legacy_comsol_unit_bundle(**kwargs)
    if job.execution_profile_id in WORKBENCH_COMSOL_RECIPE_PROFILES:
        return _build_recipe_comsol_unit_bundle(**kwargs)
    raise ValueError("COMSOL bundle requires a registered fixed Workbench profile")


def build_safe_fake_unit_bundle(
    *,
    job: JobEnvelope,
    assignment: Assignment,
    external_run_id: str,
    config: MachineExecutionConfig,
    runtime_version: str,
    output_zip: Path,
) -> Path:
    """Build a sealed fixed-function task with no user-provided command."""
    if job.execution_profile_id != SAFE_FAKE_PROFILE_ID:
        raise ValueError("safe fake bundle requires the registered safe fake profile")
    unit = next(unit for unit in job.work_units if unit.work_unit_id == assignment.work_unit_id)
    if set(unit.payload) != {"kind", "acceptance_nonce"} or unit.payload.get("kind") != "rcn_safe_fake_task":
        raise ValueError("safe fake profile accepts only the fixed acceptance payload")
    nonce = unit.payload.get("acceptance_nonce")
    if not isinstance(nonce, str) or not nonce or len(nonce) > 128:
        raise ValueError("safe fake acceptance nonce is invalid")
    if any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for character in nonce):
        raise ValueError("safe fake acceptance nonce is unsafe")

    layout = RemoteLayout.from_string(config.remote_root)
    run_dir = layout.active_run(job.project_id, job.job_id, unit.work_unit_id)
    output_dir = run_dir / "output"
    job_payload = {
        "schema_version": 1,
        "profile_id": SAFE_FAKE_PROFILE_ID,
        "acceptance_nonce": nonce,
        "duration_seconds": SAFE_FAKE_DURATION_SECONDS,
        "out_manifest": str(output_dir / "safe-fake-result.json"),
    }
    request_hash = sha256_value({
        "job_request_hash": job.request_hash,
        "unit": _immutable_unit_identity(unit),
        "runtime_version": runtime_version,
        "profile_id": SAFE_FAKE_PROFILE_ID,
    })
    staging = output_zip.parent / (output_zip.stem + "-files")
    if staging.exists():
        shutil.rmtree(staging)
    (staging / "input").mkdir(parents=True)
    job_path = staging / "input" / "job.json"
    job_path.write_text(json.dumps(job_payload, indent=2), encoding="utf-8")
    records = [{
        "path": "input/job.json",
        "size_bytes": job_path.stat().st_size,
        "sha256": sha256_file(job_path),
    }]
    request = {
        **_dispatch_payload(assignment),
        "schema_version": 1,
        "external_run_id": external_run_id,
        "machine_id": config.machine_id,
        "project_id": job.project_id,
        "job_id": job.job_id,
        "work_unit_id": unit.work_unit_id,
        "request_hash": request_hash,
        "profile_id": SAFE_FAKE_PROFILE_ID,
        "runtime_version": runtime_version,
        "resolved_resources": _resolved_resource_payload(unit, assignment.attempt_id),
        "files": records,
    }
    (staging / "request.json").write_text(json.dumps(request, indent=2), encoding="utf-8")
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(staging).as_posix())
    shutil.rmtree(staging)
    return output_zip


def build_project_worker_unit_bundle(
    *,
    project_root: Path,
    entrypoint: str,
    project_files: list[str],
    arguments: dict,
    job: JobEnvelope,
    assignment: Assignment,
    external_run_id: str,
    config: MachineExecutionConfig,
    runtime_version: str,
    output_zip: Path,
) -> Path:
    """Build a relative-path-only project worker bundle.

    Dependencies are intentionally not installed from the task.  The remote
    runtime must already be registered and hash locked.
    """
    if job.execution_profile_id != PROJECT_WORKER_PROFILE_ID:
        raise ValueError("project worker bundle requires project-worker-v1")
    root = Path(project_root).resolve()
    if not root.is_dir():
        raise FileNotFoundError(root)
    entry = PurePosixPath(entrypoint)
    if entry.is_absolute() or ".." in entry.parts or not entry.parts:
        raise ValueError("entrypoint must be a project-relative path")
    entry_path = (root / Path(*entry.parts)).resolve()
    entry_path.relative_to(root)
    if not entry_path.is_file() or entry_path.suffix.lower() != ".py":
        raise ValueError("entrypoint must be an existing project-relative Python file")
    unit = next(unit for unit in job.work_units if unit.work_unit_id == assignment.work_unit_id)
    payload = unit.payload
    if payload.get("kind") != PROJECT_WORKER_PROFILE_ID:
        raise ValueError("work unit is not a project-worker task")
    if payload.get("entrypoint") != entrypoint:
        raise ValueError("payload entrypoint does not match the bundle entrypoint")
    staging = output_zip.parent / (output_zip.stem + "-files")
    if staging.exists():
        shutil.rmtree(staging)
    project_dest = staging / "input" / "project"
    project_dest.mkdir(parents=True)
    selected = set(project_files) | {entrypoint}
    records = []
    for relative_text in sorted(selected):
        relative = PurePosixPath(relative_text)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError("project file path must be relative")
        source = (root / Path(*relative.parts)).resolve()
        source.relative_to(root)
        if not source.is_file():
            raise FileNotFoundError(source)
        destination = project_dest / Path(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    job_payload = {
        "schema_version": 1,
        "profile_id": PROJECT_WORKER_PROFILE_ID,
        "entrypoint": entrypoint,
        "arguments": arguments,
        "out_manifest": "output/project-worker-manifest.json",
        "timeout_seconds": min(3600, max(1, int(unit.expected_duration_s))),
    }
    job_path = staging / "input" / "job.json"
    job_path.write_text(json.dumps(job_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    for path in sorted((staging / "input").rglob("*")):
        if path.is_file():
            records.append({
                "path": path.relative_to(staging).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            })
    request_hash = sha256_value({
        "job_request_hash": job.request_hash,
        "unit": _immutable_unit_identity(unit),
        "runtime_version": runtime_version,
        "profile_id": PROJECT_WORKER_PROFILE_ID,
        "files": records,
    })
    request = {
        **_dispatch_payload(assignment),
        "schema_version": 1,
        "external_run_id": external_run_id,
        "machine_id": config.machine_id,
        "project_id": job.project_id,
        "job_id": job.job_id,
        "work_unit_id": unit.work_unit_id,
        "request_hash": request_hash,
        "profile_id": PROJECT_WORKER_PROFILE_ID,
        "runtime_version": runtime_version,
        "resolved_resources": _resolved_resource_payload(unit, assignment.attempt_id),
        "files": records,
    }
    (staging / "request.json").write_text(json.dumps(request, indent=2), encoding="utf-8")
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(staging).as_posix())
    shutil.rmtree(staging)
    return output_zip


def merge_chunk_outputs(chunk_roots: list[Path], destination: Path) -> tuple[Path, Path]:
    destination.mkdir(parents=True, exist_ok=True)
    rows = []
    headers = None
    manifests = []
    for root in chunk_roots:
        csv_path = next(root.rglob("chunk_*.csv"))
        manifest_path = next(root.rglob("chunk_*_manifest.json"))
        with csv_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            headers = headers or reader.fieldnames
            rows.extend(reader)
        manifests.append(json.loads(manifest_path.read_text(encoding="utf-8")))
    rows.sort(key=lambda row: (int(row["k_idx"]), int(row["band_idx"])))
    merged_csv = destination / "scan.csv"
    with merged_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    files = [entry for manifest in manifests for entry in manifest.get("files", [])]
    files.sort(key=lambda entry: (entry.get("k_idx", 0), entry.get("band_idx", 0)))
    merged_manifest = destination / "manifest.json"
    merged_manifest.write_text(json.dumps({
        "schema_version": 3,
        "n_k": len({int(row["k_idx"]) for row in rows}),
        "n_modes": max((int(row["band_idx"]) for row in rows), default=-1) + 1,
        "files": files,
    }, indent=2), encoding="utf-8")
    return merged_csv, merged_manifest
