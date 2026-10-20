"""Atomic pressure-override confirmations and durable original-ticket results."""
from __future__ import annotations

from datetime import datetime, timezone
from functools import wraps

from sqlalchemy import DateTime, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .models import MachineOperationalStatus
from .repository import Base


class PressureOverrideReceiptRow(Base):
    __tablename__ = "pressure_override_receipts"

    ticket_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(160), nullable=False)
    machine_id: Mapped[str] = mapped_column(String(160), nullable=False)
    confirmation_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    committed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    result_status: Mapped[dict] = mapped_column(JSON, nullable=False)


def pressure_override_receipt(repository, ticket_id: str, actor_id: str) -> dict | None:
    """Return the committed result, never a new override or an extended TTL."""
    with repository._session() as session:
        row = session.get(PressureOverrideReceiptRow, ticket_id)
        if row is None:
            return None
        if row.actor_id != actor_id:
            raise ValueError("operation belongs to another actor")
        result = MachineOperationalStatus.model_validate(row.result_status).model_dump(mode="json")
        return {"request_id": row.ticket_id, "kind": "pressure_override",
                "subject_id": row.machine_id, "result_id": row.machine_id,
                "state": "completed", "result": result,
                "requested_until": result["pressure_override_until"]}


def pressure_confirmation(function):
    @wraps(function)
    def wrapped(self, machine_id, *, ticket_id, confirmation_hash, actor_id):
        with self.repository.atomic_write():
            with self.repository._session() as session:
                row = session.get(PressureOverrideReceiptRow, ticket_id)
                if row is not None:
                    if (row.actor_id, row.machine_id, row.confirmation_hash) != (
                            actor_id, machine_id, confirmation_hash):
                        raise ValueError("operation identity conflicts with original pressure override")
                    return MachineOperationalStatus.model_validate(row.result_status)
            result = function(self, machine_id, ticket_id=ticket_id,
                confirmation_hash=confirmation_hash, actor_id=actor_id)
            with self.repository._session() as session:
                session.add(PressureOverrideReceiptRow(ticket_id=ticket_id, actor_id=actor_id,
                    machine_id=machine_id, confirmation_hash=confirmation_hash,
                    committed_at=datetime.now(timezone.utc), result_status=result.model_dump(mode="json")))
                session.flush()
            return result
    return wrapped
