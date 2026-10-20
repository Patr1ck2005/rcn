"""Durable, fenced continuation of cancel -> pin -> retry on the original attempt."""
from functools import wraps
import threading
from contextlib import nullcontext
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy import String, select
from sqlalchemy.orm import Mapped, mapped_column

from .repository import Base, JobRow


class UnitReassignmentRow(Base):
    __tablename__ = "unit_reassignment_operations"
    operation_id: Mapped[str] = mapped_column(String, primary_key=True)
    actor_id: Mapped[str] = mapped_column(String, nullable=False)
    job_id: Mapped[str] = mapped_column(String, nullable=False)
    work_unit_id: Mapped[str] = mapped_column(String, nullable=False)
    target_machine_id: Mapped[str] = mapped_column(String, nullable=False)
    reason: Mapped[str] = mapped_column(String, nullable=False)
    expected_attempt_id: Mapped[str] = mapped_column(String, nullable=False)
    expected_external_run_id: Mapped[str] = mapped_column(String, nullable=False)
    stage: Mapped[str] = mapped_column(String, nullable=False)


def _result(repository, row):
    return {"stage": row.stage, "job": repository.get_job(row.job_id),
            "operation_id": row.operation_id, "target_machine_id": row.target_machine_id,
            "expected_attempt_id": row.expected_attempt_id or None,
            "expected_external_run_id": row.expected_external_run_id or None}


def reassignment_result(repository, operation_id, *, job_id, work_unit_id, actor_id):
    operation_id = str(UUID(operation_id))
    with repository._session() as session:
        row = session.get(UnitReassignmentRow, operation_id)
        if row is None:
            raise KeyError("reassignment operation not found")
        if (row.actor_id, row.job_id, row.work_unit_id) != (actor_id, job_id, work_unit_id):
            raise ValueError("reassignment operation belongs to another actor or unit")
        return _result(repository, row)


def fenced_reassignment(function):
    @wraps(function)
    def wrapped(self, job_id, work_unit_id, target_machine_id, *, actor_id, reason="",
                operation_id=None, expected_attempt_id=None, expected_external_run_id=None):
        explicit = operation_id is not None
        target_machine_id, reason = str(target_machine_id or "").strip(), reason.strip()
        # Legacy clients have no request UUID. Repeating their identical intent must
        # continue/replay the same operation, never silently target a successor.
        operation_id = str(UUID(operation_id)) if explicit else str(uuid5(
            NAMESPACE_URL, repr(("rcn-reassign", actor_id, job_id, work_unit_id, target_machine_id, reason))))
        # Use the same lock order as ordinary mutate_job: local Job then DB.
        # Taking BEGIN IMMEDIATE first could deadlock a dispatcher holding the Job.
        with self.repository._job_locks_guard:
            job_lock = self.repository._job_locks.setdefault(job_id, threading.RLock())
        with (job_lock if self.repository._transaction_session() is None else nullcontext()), self.repository.atomic_write():
            with self.repository._session() as session:
                if self.repository.engine.dialect.name != "sqlite":
                    session.scalar(select(JobRow).where(JobRow.job_id == job_id).with_for_update())
                row = session.get(UnitReassignmentRow, operation_id)
                if row is not None:
                    if (row.actor_id, row.job_id, row.work_unit_id, row.target_machine_id, row.reason) != (
                            actor_id, job_id, work_unit_id, target_machine_id, reason):
                        raise ValueError("reassignment operation conflicts with original request")
                    if explicit and (row.expected_attempt_id, row.expected_external_run_id) != (
                            expected_attempt_id or "", expected_external_run_id or ""):
                        raise ValueError("reassignment identity conflicts with original request")
                    if row.stage == "reassigned":
                        return _result(self.repository, row)
                job = self.repository.get_job(job_id)
                if job is None:
                    raise KeyError(f"job not found: {job_id}")
                unit = next((u for u in job.work_units if u.work_unit_id == work_unit_id), None)
                if unit is None:
                    raise KeyError(f"work unit not found: {work_unit_id}")
                latest = unit.attempts[-1] if unit.attempts else None
                current = (latest.attempt_id if latest else "", (latest.external_run_id or "") if latest else "")
                expected = ((row.expected_attempt_id, row.expected_external_run_id) if row is not None else
                            ((expected_attempt_id or "", expected_external_run_id or "") if explicit else current))
                if current != expected:
                    raise ValueError("attempt_changed: original reassignment cannot act on a successor Attempt")
                if row is not None and latest is not None and latest.state == "cancel_pending":
                    return _result(self.repository, row)
                if row is None:
                    row = UnitReassignmentRow(operation_id=operation_id, actor_id=actor_id, job_id=job_id,
                        work_unit_id=work_unit_id, target_machine_id=target_machine_id, reason=reason,
                        expected_attempt_id=expected[0], expected_external_run_id=expected[1], stage="cancel_requested")
                    session.add(row)
                    self._event("work_unit.reassignment_intent", actor_id, "work_unit", work_unit_id,
                        job_id=job_id, operation_id=operation_id, expected_attempt_id=expected[0],
                        expected_external_run_id=expected[1], target_machine_id=target_machine_id, reason=reason)
                outcome = function(self, job_id, work_unit_id, target_machine_id, actor_id=actor_id, reason=reason)
                row.stage = outcome["stage"]
                session.flush()
                return _result(self.repository, row)
    return wrapped
