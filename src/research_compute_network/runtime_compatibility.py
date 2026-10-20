"""Explicitly approved, scientifically identical execution-runtime successors.

Runtime hashes remain exact on every dispatched Attempt.  A successor is a
separately approved environment with an evidence hash and an explicit link to
the original approval; sharing a template name or being a newer version alone
does not establish equivalence.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from .models import SolverCompatibilityApproval


_SCIENCE_FIELDS = (
    "project_id",
    "execution_profile_id",
    "comsol_version",
    "template_sha256",
    "template_role",
    "allowed_study_kinds",
    "template_hash_policy",
    "mesh_policy",
    "solver_variants",
)


def same_scientific_environment(
    original: SolverCompatibilityApproval,
    candidate: SolverCompatibilityApproval,
) -> bool:
    """Require equality of every approved scientific execution field."""
    return all(getattr(original, name) == getattr(candidate, name) for name in _SCIENCE_FIELDS)


def is_registered_runtime_successor(
    original: SolverCompatibilityApproval,
    candidate: SolverCompatibilityApproval,
    *,
    now: datetime | None = None,
) -> bool:
    """Check a direct, active administrator-approved equivalence relation."""
    return bool(
        original.is_active(now)
        and candidate.is_active(now)
        and original.approval_id != candidate.approval_id
        and original.runtime_version
        and candidate.runtime_version
        and original.runtime_version != candidate.runtime_version
        and getattr(candidate, "runtime_predecessor_approval_id", None) == original.approval_id
        and getattr(candidate, "runtime_equivalence_sha256", None)
        and same_scientific_environment(original, candidate)
    )


def select_execution_approval(
    original: SolverCompatibilityApproval,
    candidates: Iterable[SolverCompatibilityApproval],
    runtime_version: str | None,
    *,
    now: datetime | None = None,
) -> SolverCompatibilityApproval | None:
    """Select an exact machine-runtime approval without mutating the original."""
    if not original.is_active(now):
        return None
    if original.runtime_version == runtime_version:
        return original
    compatible = [
        candidate
        for candidate in candidates
        if candidate.runtime_version == runtime_version
        and is_registered_runtime_successor(original, candidate, now=now)
    ]
    return max(compatible, key=lambda value: (value.created_at, value.approval_id), default=None)


def select_machine_execution_approval(original, candidates, machine, config, *, now=None):
    """Prefer the primary runtime, then an admitted exact cached runtime.

    Cached execution preserves the original scientific approval. It does not
    register an equivalence between different scientific worker versions.
    """
    if config is None or config.runtime_version != machine.runtime_version:
        return None
    candidates = list(candidates)
    primary = select_execution_approval(original, candidates, machine.runtime_version, now=now)
    if primary is not None:
        return primary
    from .runtime_cache_admission import accepted_cache_admissions
    versions = {record.cache_runtime for record in accepted_cache_admissions(machine, config)}
    if original.is_active(now) and original.runtime_version in versions:
        return original
    matches = [candidate for candidate in candidates
               if candidate.runtime_version in versions
               and is_registered_runtime_successor(original, candidate, now=now)]
    return max(matches, key=lambda item: (item.created_at, item.approval_id), default=None)


def equivalence_root_approval_id(
    approval: SolverCompatibilityApproval,
    candidates: Iterable[SolverCompatibilityApproval],
) -> str:
    """Identify evidence reuse only across the same registered scientific pair."""
    predecessor_id = getattr(approval, "runtime_predecessor_approval_id", None)
    if predecessor_id:
        predecessor = next((item for item in candidates if item.approval_id == predecessor_id), None)
        if predecessor is not None and is_registered_runtime_successor(predecessor, approval):
            return predecessor.approval_id
    return approval.approval_id
