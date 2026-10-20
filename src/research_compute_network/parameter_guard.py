"""Shared planning and sealing guards for template-controlled parameters."""

from __future__ import annotations

import json
from typing import Any

from .models import JobEnvelope, PartitionRequest, TemplateParameterEvidence
from .remote_agent.template_build_contracts import (
    validate_template_build_envelope,
)

from .remote_agent.saved_readout_contracts import validate_saved_readout_envelope


GENERIC_STUDY_PROFILE_ID = "workbench-comsol-study-v1"
GENERIC_STUDY_PROFILE_IDS = {GENERIC_STUDY_PROFILE_ID, "workbench-comsol-study-v2"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _validate_items(
    *,
    profile_id: str,
    study_kind: object,
    template_sha256: str | None,
    evidence: TemplateParameterEvidence | None,
    items: list[dict[str, Any]],
) -> None:
    if profile_id in GENERIC_STUDY_PROFILE_IDS and evidence is None:
        raise ValueError(
            "workbench-comsol-study-v1 requires template_parameter_evidence from template inspection"
        )
    if evidence is None:
        return
    if template_sha256 != evidence.template_sha256:
        raise ValueError("template parameter evidence does not match the request template SHA-256")

    model_parameters = set(evidence.global_parameter_names)
    coordinate_sets: set[str] = set()
    execution_states: set[str] = set()
    for item in items:
        coordinates = item.get("coordinates")
        payload = item.get("payload")
        if not isinstance(coordinates, dict) or not isinstance(payload, dict):
            raise ValueError("atomic item payload and coordinates must be mappings")
        payload_template = payload.get("template_sha256")
        if payload_template is not None and payload_template != evidence.template_sha256:
            raise ValueError("atomic item template SHA-256 does not match template parameter evidence")
        payload_inspection = payload.get("template_inspection_sha256")
        if profile_id in GENERIC_STUDY_PROFILE_IDS and payload_inspection != evidence.inspection_sha256:
            raise ValueError("atomic item template inspection SHA-256 does not match parameter evidence")
        if payload_inspection is not None and payload_inspection != evidence.inspection_sha256:
            raise ValueError("atomic item template inspection SHA-256 does not match parameter evidence")

        setup = payload.get("setup_parameters", {})
        sweep = payload.get("sweep_parameters", {})
        if not isinstance(setup, dict) or not isinstance(sweep, dict):
            raise ValueError("setup_parameters and sweep_parameters must be mappings")
        for name in sorted(set(coordinates) & model_parameters):
            if name not in setup and name not in sweep:
                raise ValueError(
                    f"coordinate-only ModelParam '{name}' must be declared in "
                    "sweep_parameters or setup_parameters; coordinates are report metadata only"
                )
        coordinate_sets.add(_canonical(coordinates))
        execution_states.add(_canonical({"setup_parameters": setup, "sweep_parameters": sweep}))

    normalized_study = getattr(study_kind, "value", study_kind)
    if (
        profile_id in GENERIC_STUDY_PROFILE_IDS
        and normalized_study == "eigenfrequency"
        and len(items) > 1
        and len(coordinate_sets) > 1
        and len(execution_states) == 1
    ):
        raise ValueError(
            "explicit multi-point eigenfrequency request changes coordinates but not execution "
            "parameters; every point would solve the same parametric state"
        )


def validate_partition_parameter_contract(request: PartitionRequest) -> None:
    validate_template_build_envelope(request, [item.model_dump(mode="json") for item in request.items])
    validate_saved_readout_envelope(request, [item.model_dump(mode="json") for item in request.items])
    _validate_items(
        profile_id=request.execution_profile_id,
        study_kind=request.study_kind,
        template_sha256=request.template_sha256,
        evidence=request.template_parameter_evidence,
        items=[item.model_dump(mode="json") for item in request.items],
    )


def validate_job_parameter_contract(job: JobEnvelope) -> None:
    items = [
        item
        for unit in job.work_units
        for item in unit.payload.get("items", [])
        if isinstance(item, dict)
    ]
    validate_template_build_envelope(job, items)
    validate_saved_readout_envelope(job, items)
    if not items and job.execution_profile_id not in GENERIC_STUDY_PROFILE_IDS:
        return
    _validate_items(
        profile_id=job.execution_profile_id,
        study_kind=job.study_kind,
        template_sha256=job.template_sha256,
        evidence=job.template_parameter_evidence,
        items=items,
    )


def validate_unit_parameter_contract(job: JobEnvelope, items: list[dict[str, Any]]) -> None:
    validate_saved_readout_envelope(job, items)
    _validate_items(
        profile_id=job.execution_profile_id,
        study_kind=job.study_kind,
        template_sha256=job.template_sha256,
        evidence=job.template_parameter_evidence,
        items=items,
    )
