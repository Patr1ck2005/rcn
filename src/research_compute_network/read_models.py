"""Rebuildable, indexed operational metadata; never scientific payloads.

Job JSON remains authoritative. These tables are replaced in its transaction,
and can be rebuilt without hydrating a single scientific storage blob.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import json
import math

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Float, Index, Integer, String, delete, insert
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


READ_MODEL_VERSION = 2
TERMINAL_ATTEMPT_STATES = frozenset({"completed", "failed", "cancelled", "abandoned"})


@dataclass(frozen=True)
class JobVisibility:
    """Union of authorized Jobs, applied before ordering and pagination.

    None at the repository boundary means unrestricted. An empty instance
    deliberately matches nothing. The caller decides which grants apply.
    """

    user_id: str | None = None
    project_ids: frozenset[str] = field(default_factory=frozenset)
    machine_ids: frozenset[str] = field(default_factory=frozenset)


class ReadModelBase(DeclarativeBase):
    pass


class ReadRevisionRow(ReadModelBase):
    """SQLite triggers advance this counter even for raw recovery SQL writes."""
    __tablename__ = "operational_read_revisions"
    scope: Mapped[str] = mapped_column(String(32), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)


class JobReadRow(ReadModelBase):
    __tablename__ = "job_read_models"
    job_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    projection_version: Mapped[int] = mapped_column(Integer, nullable=False)
    user_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    effective_status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    activity_state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    execution_profile_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    total_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    completed_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    migrated_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    infrastructure_failures: Mapped[int] = mapped_column(Integer, nullable=False)
    pending_reconciliation: Mapped[int] = mapped_column(Integer, nullable=False)
    summary_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    insight_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


class UnitReadRow(ReadModelBase):
    __tablename__ = "unit_read_models"
    job_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    work_unit_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    assigned_machine_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    actual_duration_s: Mapped[float | None] = mapped_column(Float, nullable=True)
    remote_recovery_pending: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    latest_attempt: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    insight_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    __table_args__ = (
        Index("ix_unit_read_machine_job", "assigned_machine_id", "job_id"),
        Index("ix_unit_read_job_ordinal", "job_id", "ordinal"),
    )


class AttemptReadRow(ReadModelBase):
    __tablename__ = "attempt_read_models"
    job_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    work_unit_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    attempt_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    machine_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    state: Mapped[str] = mapped_column(String(40), nullable=False)
    failure_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    migrated: Mapped[bool] = mapped_column(Boolean, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    allocated_cpus: Mapped[float | None] = mapped_column(Float, nullable=True)
    started_epoch_us: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    finished_epoch_us: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    __table_args__ = (
        Index("ix_attempt_read_machine_state", "machine_id", "state", "attempt_id"),
        Index("ix_attempt_read_state_machine", "state", "machine_id"),
        Index("ix_attempt_read_identity_job", "attempt_id", "job_id"),
    )


def _datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if not isinstance(value, datetime):
        value = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def epoch_microseconds(value: datetime | None) -> int | None:
    if value is None:
        return None
    delta = value-datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days*86400+delta.seconds)*1000000+delta.microseconds


def job_lifecycle(projection: dict[str, Any]) -> tuple[str, str]:
    """Match the public operational-summary lifecycle without loading history."""
    units = projection.get("work_units") or []
    statuses = {unit.get("status") for unit in units}
    recorded = str(projection.get("status") or "awaiting_approval")
    retryable = any(
        unit.get("status") == "failed_retriable"
        and int(unit.get("attempt_count") or 0) < int(unit.get("max_attempts") or 0)
        and unit.get("attempts")
        and unit["attempts"][-1].get("state") == "failed"
        and unit["attempts"][-1].get("failure_class") in {"infrastructure", "resource_exhaustion"}
        for unit in units
    )
    if statuses.intersection({"assigned", "running", "reconcile_pending", "collecting"}):
        status = "running"
    elif recorded in {"awaiting_approval", "awaiting_environment", "blocked"} and statuses.issubset({"queued", "prepared", "staged"}):
        status = recorded
    elif "queued" in statuses:
        status = "queued"
    elif retryable:
        status = "failed_retriable"
    elif units and statuses == {"completed"}:
        status = "completed"
    elif "cancelled" in statuses:
        status = "cancelled"
    elif units:
        status = "failed_terminal"
    else:
        status = recorded
    activity = {
        "running": "active", "queued": "queued", "failed_retriable": "recoverable",
        "failed_terminal": "history", "completed": "history", "cancelled": "history",
        "awaiting_approval": "queued", "awaiting_environment": "queued",
    }.get(status, "needs_attention")
    return status, activity


def replace_job_read_model(session: Session, projection: dict[str, Any]) -> None:
    """Replace one aggregate's metadata inside the caller's Job transaction."""
    job_id = str(projection["job_id"])
    status, activity = job_lifecycle(projection)
    summary = {key: value for key, value in projection.items() if key not in {"work_units", "projection_version"}}
    session.execute(delete(AttemptReadRow).where(AttemptReadRow.job_id == job_id))
    session.execute(delete(UnitReadRow).where(UnitReadRow.job_id == job_id))
    units = []
    attempts = []
    for unit in projection.get("work_units") or []:
        unit_id = str(unit["work_unit_id"])
        history = unit.get("attempts") or []
        latest = history[-1] if history else {}
        remote_recovery_pending = bool(
            unit.get("status") not in {"completed", "cancelled"}
            and latest.get("state") == "failed"
            and latest.get("failure_class") == "infrastructure"
            and latest.get("external_run_id") and not latest.get("execution_completed")
            and str(latest.get("failure_reason") or unit.get("failure_reason") or "").startswith("remote state remained uncertain:")
        )
        insight = {key: unit.get(key) for key in (
            "work_unit_id", "status", "expected_duration_s", "actual_duration_s",
            "assigned_machine_id", "eta_s", "updated_at", "resources", "resolved_resources",
        )}
        starts = [_datetime(a.get("started_at")) for a in history if a.get("started_at")]
        first = min(starts) if starts else None
        success = next((a for a in reversed(history) if a.get("state") == "completed"), {})
        insight["_first_attempt_started_at"] = first.isoformat() if first else None
        insight["_successful_finished_at"] = success.get("collected_at") or success.get("finished_at")
        pending = {a.get("state") for a in history if a.get("state") in {
            "assigned", "running", "collecting", "reconcile_pending", "uncertain", "cancel_pending", "submitting"}}
        if remote_recovery_pending:
            pending.add("failed")
        insight["_pending_states"] = sorted(pending)
        insight["attempts"] = [{key: latest.get(key) for key in (
            "attempt_id", "state", "machine_id", "started_at", "last_observed_at",
        )}] if latest else []
        units.append({
            "job_id": job_id, "work_unit_id": unit_id, "ordinal": int(unit.get("ordinal") or 0),
            "status": str(unit.get("status") or "queued"),
            "assigned_machine_id": unit.get("assigned_machine_id"),
            "actual_duration_s": unit.get("actual_duration_s"),
            "remote_recovery_pending": remote_recovery_pending,
            "payload": {key: value for key, value in unit.items() if key not in {"attempts", "payload", "atomic_item_ids"}},
            "latest_attempt": history[-1] if history else None,
            "insight_payload": insight,
        })
        # A malformed repeated identity must not multiply capacity counts.
        unique = {str(item["attempt_id"]): item for item in history}
        for attempt_id, attempt in unique.items():
            resources = ((attempt.get("resolved_resources") or {}).get("resources")
                or (unit.get("resolved_resources") or {}).get("resources") or unit.get("resources") or {})
            cpus = resources.get("cpus")
            try:
                cpus = float(cpus) if not isinstance(cpus, bool) else 0.0
                if not math.isfinite(cpus) or not 0 <= cpus <= 1e15:
                    cpus = 0.0
            except (TypeError, ValueError, OverflowError):
                cpus = 0.0
            attempts.append({
                "job_id": job_id, "work_unit_id": unit_id, "attempt_id": attempt_id,
                "machine_id": attempt.get("machine_id"), "state": str(attempt.get("state") or "assigned"),
                "failure_class": attempt.get("failure_class"), "migrated": bool(attempt.get("migrated")),
                "started_at": _datetime(attempt.get("started_at")),
                "finished_at": _datetime(attempt.get("finished_at")),
                "collected_at": _datetime(attempt.get("collected_at")),
                "allocated_cpus": cpus,
                "started_epoch_us": epoch_microseconds(_datetime(attempt.get("started_at"))),
                "finished_epoch_us": epoch_microseconds(_datetime(attempt.get("finished_at"))),
            })
    session.merge(JobReadRow(
        job_id=job_id, revision=int(projection.get("revision") or 0),
        user_id=str(projection.get("user_id") or ""), project_id=str(projection.get("project_id") or ""),
        status=str(projection.get("status") or "awaiting_approval"), created_at=_datetime(projection["created_at"]),
        projection_version=READ_MODEL_VERSION, effective_status=status,
        activity_state=activity, execution_profile_id=str(projection.get("execution_profile_id") or ""),
        total_attempts=len(attempts),
        completed_attempts=sum(item["state"] == "completed" for item in attempts),
        migrated_attempts=sum(item["migrated"] for item in attempts),
        infrastructure_failures=sum(item["state"] == "failed" and item["failure_class"] == "infrastructure" for item in attempts),
        pending_reconciliation=sum(item["state"] in {"reconcile_pending", "uncertain"} for item in attempts),
        summary_payload=summary,
        insight_payload={**{key: projection.get(key) for key in (
            "job_id", "project_id", "user_id", "status", "record_class", "created_at", "updated_at")},
            "_unit_count": len(units), "_operational_chars": len(json.dumps(projection))},
    ))
    if units:
        session.execute(insert(UnitReadRow), units)
    if attempts:
        session.execute(insert(AttemptReadRow), attempts)
