"""Atomic control confirmation and durable replay without repeated remote I/O."""
from __future__ import annotations

from functools import wraps
from datetime import timezone

from sqlalchemy import Boolean, JSON, String, select
from sqlalchemy.orm import Mapped, mapped_column

from .models import (ControlOperationRun, ControlTargetResult, ControlTargetState,
                     MachineCommand, MachineCommandResult, MachineControlAction, utc_now)
from .repository import Base, ControlOperationRunRow


def atomic_metadata(function):
    @wraps(function)
    def wrapped(self, *args, **kwargs):
        with self.repository.atomic_write():
            return function(self, *args, **kwargs)
    return wrapped


class ControlConfirmationRow(Base):
    __tablename__ = "control_confirmation_receipts"
    ticket_id: Mapped[str] = mapped_column(String, primary_key=True)
    confirmation_hash: Mapped[str] = mapped_column(String, nullable=False)
    actor_id: Mapped[str] = mapped_column(String, nullable=False)
    operation_id: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    execution_claimed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    command_payloads: Mapped[list] = mapped_column(JSON, nullable=False, default=list)


def claim_control_execution(repository, ticket_id):
    with repository.atomic_write():
        with repository._session() as session, session.begin():
            receipt = session.get(ControlConfirmationRow, ticket_id)
            if receipt is None or receipt.execution_claimed:
                return False
            receipt.execution_claimed = True
            session.flush()
            return True


def control_by_ticket(repository, ticket_id, *, actor_id=None, confirmation_hash=None):
    with repository._session() as session:
        receipt = session.get(ControlConfirmationRow, ticket_id)
        if receipt is not None:
            if actor_id is not None and receipt.actor_id != actor_id:
                raise ValueError("control ticket belongs to another operator")
            if confirmation_hash is not None and receipt.confirmation_hash != confirmation_hash:
                raise ValueError("control confirmation does not match the original request")
            row = session.get(ControlOperationRunRow, receipt.operation_id)
            if row is None:
                raise ValueError("durable control receipt requires operator reconciliation")
            return ControlOperationRun.model_validate(row.payload)
        return None


def atomic_confirmation(kind):
    def decorate(function):
        @wraps(function)
        def wrapped(self, ticket_id, confirmation_hash, *args, **kwargs):
            with self.repository.atomic_write():
                old = control_by_ticket(self.repository, ticket_id,
                    actor_id=kwargs["actor_id"], confirmation_hash=confirmation_hash)
                if old is not None:
                    return (old, []) if kind == "machine" else old
                result = function(self, ticket_id, confirmation_hash, *args, **kwargs)
                run = result[0] if kind == "machine" else result
                with self.repository._session() as session, session.begin():
                    session.add(ControlConfirmationRow(ticket_id=ticket_id,
                        confirmation_hash=confirmation_hash, actor_id=kwargs["actor_id"],
                        operation_id=run.operation_id, kind=kind,
                        command_payloads=[c.model_dump(mode="json") for c in result[1]] if kind == "machine" else []))
                    session.flush()
                return result
        return wrapped
    return decorate


IMMEDIATE_MACHINE_ACTIONS = frozenset({MachineControlAction.RESTART_SUPERVISOR,
                                       MachineControlAction.FORCE_RESTART_SUPERVISOR})
INBOX_MACHINE_ACTIONS = frozenset({MachineControlAction.HEALTH_PROBE, MachineControlAction.SET_TARGET_CAPACITY,
    MachineControlAction.SET_HARD_CAPACITY, MachineControlAction.GRACEFUL_STOP,
    MachineControlAction.EMERGENCY_STOP_NETWORK, MachineControlAction.EMERGENCY_STOP_HOST})


def recover_control_delivery(service, operation_id, *, transport_for, actor_id="control-delivery-recovery"):
    """Recover the original durable inbox message, never create another command.

    Read persisted/remote results first. Inbox delivery may repeat the exact
    command id, nonce and expiry. Immediate actions have no deduplicated inbox;
    uncertain execution is surfaced for reconciliation instead of being replayed.
    """
    repository = service.repository
    run = repository.get_control_operation_run(operation_id)
    if run is None:
        raise KeyError("control operation not found")
    with repository._session() as session:
        receipt = session.scalar(select(ControlConfirmationRow).where(
            ControlConfirmationRow.operation_id == operation_id))
        if receipt is None:
            return run  # Legacy operations retain their existing result polling.
        kind, payloads = receipt.kind, list(receipt.command_payloads or [])

    def update(target, state, message):
        # Serializes the fresh target read with its update, including audit.
        with repository.atomic_write():
            current = repository.get_control_operation_run(operation_id)
            found = next((t for t in current.targets if t.machine_id == target.machine_id), None)
            if found is None or found.state in {ControlTargetState.COMPLETED, ControlTargetState.FAILED}:
                return
            if found.state == state and found.message == message:
                return
            service.update_control_target(operation_id, ControlTargetResult(machine_id=target.machine_id,
                command_id=target.command_id, state=state, message=message), actor_id=actor_id)

    def record(command, payload):
        result = MachineCommandResult.model_validate(payload)
        if (result.command_id != command.command_id or result.machine_id != command.machine_id
                or result.action != command.action):
            raise ValueError("machine_command_result_identity_mismatch")
        with repository.atomic_write():
            repository.put_machine_command_result(result)
            service.update_control_target(operation_id, ControlTargetResult(machine_id=result.machine_id,
                command_id=result.command_id, state=result.state, message=result.message,
                updated_at=result.completed_at or result.created_at), actor_id=actor_id)

    commands = {}
    for payload in payloads:
        command = MachineCommand.model_validate(payload)
        if command.command_id in commands:
            raise ValueError("duplicate durable machine command identity")
        commands[command.command_id] = command
    for target in run.targets:
        if target.state == ControlTargetState.COMPLETED:
            continue
        command = commands.get(target.command_id)
        if kind != "machine" or command is None:
            update(target, ControlTargetState.FAILED,
                   "reconciliation_required: original immediate action delivery cannot be confirmed")
            continue
        if command.machine_id != target.machine_id or command.action != run.action:
            update(target, ControlTargetState.FAILED,
                   "reconciliation_required: durable command differs from original control operation")
            continue
        local = repository.get_machine_command_result(command.command_id)
        expiry = command.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        try:
            if local is not None:
                record(command, local.model_dump(mode="json"))
                continue
            if command.action in IMMEDIATE_MACHINE_ACTIONS or command.action not in INBOX_MACHINE_ACTIONS:
                update(target, ControlTargetState.FAILED,
                       "reconciliation_required: immediate action may have executed; automatic replay is disabled")
                continue
            transport = transport_for(command.machine_id)
            result = transport.read_machine_command_result(command.command_id)
            if result is not None:
                record(command, result)
                continue
            if target.state == ControlTargetState.FAILED:
                continue  # A late result may resolve it; never reissue a failed command.
            if expiry <= utc_now():
                update(target, ControlTargetState.FAILED,
                       "reconciliation_required: original command expired; its expiry was not extended")
                continue
            transport.submit_machine_command(command.model_dump(mode="json"))
            # The worker can consume the file before submit's landing check.
            # Prefer its result over acknowledging an already completed action.
            result = transport.read_machine_command_result(command.command_id)
            if result is not None:
                record(command, result)
            else:
                update(target, ControlTargetState.ACKNOWLEDGED,
                       "remote supervisor accepted the original command file")
        except ValueError:
            update(target, ControlTargetState.FAILED,
                   "reconciliation_required: original command or result identity requires review")
        except (OSError, RuntimeError) as exc:
            if expiry <= utc_now():
                update(target, ControlTargetState.FAILED,
                       "reconciliation_required: original command expired without a confirmed result")
            elif str(exc).startswith("reconciliation_required:"):
                update(target, ControlTargetState.FAILED,
                       "reconciliation_required: remote consumed the original command without a confirmed result")
            else:
                update(target, target.state,
                       "delivery_pending: preserve the original command for result lookup or deduplicated retry")
    return repository.get_control_operation_run(operation_id)
