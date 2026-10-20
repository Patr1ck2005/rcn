"""Authenticated administrative changes to future scheduling resources."""

from __future__ import annotations

import re
import copy
from typing import TYPE_CHECKING

from sqlalchemy import exists, text, update

from .auth import AuthContext, require_role
from .models import ResolvedResources, UserRole, WorkUnitStatus, utc_now
from .repository import (
    DispatchReservationRow, JobRow, RevisionConflictError,
    _stored_job_operational_projection,
)

if TYPE_CHECKING:
    from .service import NetworkService


def increase_queued_job_memory(
    service: NetworkService,
    context: AuthContext,
    job_id: str,
    memory_mb: int,
    reason: str,
    evidence_sha256: str,
    evidence_sample_count: int,
    expected_revision: int,
) -> dict:
    """Raise a queued Unit's future floor without rewriting Attempts or science.

    The caller must obtain ``context`` from the installed authenticator. This
    module provides no token bypass, CLI, submission, or remote-shell interface.
    Lower/equal floors are harmless no-ops when already satisfied. Both resource
    envelopes retain the largest existing memory allocation. A concurrent Job
    update (including standby preparation) aborts the single CAS without replay.
    """
    require_role(context, UserRole.ADMIN)
    if isinstance(memory_mb, bool) or not isinstance(memory_mb, int) or memory_mb < 256:
        raise ValueError("memory_mb must be an integer of at least 256 MiB")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("an audit reason is required")
    if not isinstance(evidence_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", evidence_sha256):
        raise ValueError("evidence_sha256 must be a 64-character SHA-256 digest")
    if (isinstance(evidence_sample_count, bool)
            or not isinstance(evidence_sample_count, int) or evidence_sample_count <= 0):
        raise ValueError("evidence_sample_count must be a positive integer")
    if (isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int) or expected_revision < 0):
        raise ValueError("expected_revision must be a nonnegative integer")

    repository = service.repository
    # Do not hydrate scientific blobs. Unlike the scheduler snapshot, this read
    # also retains nullable fields without inventing progress denominators.
    job = repository.get_job(job_id, hydrate_blobs=False)
    if job is None:
        raise KeyError(f"job not found: {job_id}")
    if job.revision != expected_revision:
        raise RevisionConflictError(
            f"stale job revision for {job_id}: expected {expected_revision}, got {job.revision}"
        )
    reserved_ids = {
        reservation.work_unit_id
        for reservation in repository.list_dispatch_reservations(job_id=job_id, active_only=True)
    }
    changes = []
    skipped = []
    for unit in job.work_units:
        skip_reason = None
        if unit.status != WorkUnitStatus.QUEUED:
            skip_reason = "unit_not_queued"
        elif any(attempt.state not in {"completed", "failed", "cancelled"} for attempt in unit.attempts):
            # Unknown states are conservatively active; preserve their ledger.
            skip_reason = "active_or_unknown_attempt"
        elif unit.work_unit_id in reserved_ids:
            skip_reason = "active_dispatch_reservation"
        if skip_reason is not None:
            skipped.append({"work_unit_id": unit.work_unit_id, "reason": skip_reason})
            continue

        old_request = unit.resources.memory_mb
        old_resolved = unit.resolved_resources.resources.memory_mb if unit.resolved_resources else None
        floor = max(memory_mb, old_request, old_resolved or 0)
        if old_request == floor and old_resolved == floor:
            skipped.append({"work_unit_id": unit.work_unit_id, "reason": "memory_floor_already_satisfied"})
            continue
        # A missing resolved envelope only needs materializing when memory rises.
        if old_request == floor and old_resolved is None:
            skipped.append({"work_unit_id": unit.work_unit_id, "reason": "memory_floor_already_satisfied"})
            continue
        unit.resources = unit.resources.model_copy(update={"memory_mb": floor})
        if unit.resolved_resources is None:
            unit.resolved_resources = ResolvedResources(
                resources=unit.resources.model_copy(), source="network_dynamic",
                evidence_sample_count=evidence_sample_count,
            )
        else:
            resolved = unit.resolved_resources
            unit.resolved_resources = resolved.model_copy(update={
                "resources": resolved.resources.model_copy(update={"memory_mb": floor}),
                "source": "network_dynamic", "evidence_sample_count": evidence_sample_count,
                "resolved_at": utc_now(),
            })
        changes.append({
            "work_unit_id": unit.work_unit_id,
            "before": {"resources_memory_mb": old_request, "resolved_memory_mb": old_resolved},
            "after": {"resources_memory_mb": floor, "resolved_memory_mb": floor},
        })

    if changes:
        # Patch the stored operational projection only. In addition to revision
        # CAS, the same SQL statement rechecks authoritative reservation rows;
        # even legacy reservation creation without Job CAS cannot slip through.
        changed_ids = [item["work_unit_id"] for item in changes]
        changed_units = {unit.work_unit_id: unit for unit in job.work_units}
        now = utc_now()
        with repository._session() as session, session.begin():
            if repository.engine.dialect.name == "sqlite":
                session.execute(text("BEGIN IMMEDIATE"))
            stored = session.get(JobRow, job_id)
            if stored is None or stored.revision != expected_revision:
                raise RevisionConflictError(f"job revision changed during memory update: {job_id}")
            projection = copy.deepcopy(stored.operational_payload or
                                       _stored_job_operational_projection(stored.payload))
            for compact in projection["work_units"]:
                if compact["work_unit_id"] in changed_ids:
                    unit = changed_units[compact["work_unit_id"]]
                    compact["resources"] = unit.resources.model_dump(mode="json")
                    compact["resolved_resources"] = unit.resolved_resources.model_dump(mode="json")
            projection.update(revision=expected_revision + 1, updated_at=now.isoformat())
            active_reservation = exists().where(
                DispatchReservationRow.job_id == job_id,
                DispatchReservationRow.work_unit_id.in_(changed_ids),
                DispatchReservationRow.active_key.is_not(None),
            )
            result = session.execute(update(JobRow).where(
                JobRow.job_id == job_id, JobRow.revision == expected_revision,
                ~active_reservation,
            ).values(revision=expected_revision + 1, updated_at=now,
                     operational_payload=projection))
            if result.rowcount != 1:
                raise RevisionConflictError(f"job or active reservation changed during memory update: {job_id}")
        job.revision = expected_revision + 1
    else:
        current = repository.get_job(job_id, hydrate_blobs=False)
        if current is None or current.revision != expected_revision:
            raise RevisionConflictError(f"job revision changed during memory check: {job_id}")
    receipt = {
        "job_id": job_id, "actor_id": context.actor_id,
        "reason": reason.strip(), "evidence_sha256": evidence_sha256.lower(),
        "evidence_sample_count": evidence_sample_count, "requested_memory_mb": memory_mb,
        "previous_revision": expected_revision, "revision": job.revision,
        "changed_unit_ids": [item["work_unit_id"] for item in changes],
        "skipped_unit_ids": [item["work_unit_id"] for item in skipped],
        "changes": changes, "skipped_units": skipped,
        "changed_unit_count": len(changes), "skipped_unit_count": len(skipped),
    }
    if changes:
        service._event(
            "job.queued_memory_increased", context.actor_id, "job", job_id,
            **{key: value for key, value in receipt.items() if key not in {"actor_id", "job_id"}},
        )
    return receipt
