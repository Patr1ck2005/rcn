"""Attempt-specific, auditable mutual-compute accounting.

CPU core-hours and GPU device-hours are separate currencies. Machine accounting
coefficients default to 1 and are frozen independently in each reservation.
Integer micro-hours avoid floating point balance races. Scientific artifacts and
credentials never enter these tables. Shadow mode records usage without denial.
Shadow balances and holds never become spendable when a switch or policy changes.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import hashlib
import json
import math
from typing import Literal

from sqlalchemy import BigInteger, Boolean, DateTime, JSON, String, select
from sqlalchemy.orm import Mapped, mapped_column

from .models import utc_now
from .repository import Base
from .credit_ledger_migration import MIGRATION_ID, SCOPES, migrate_legacy_credits
from .submission_policy import (PersonSubmissionPolicyRow, SubmissionPolicyError,
                                _append_audit, _require_admin, _serialized_write)

UNITS_PER_HOUR = 1_000_000
Pool = Literal["mutual", "free_idle"]


class CreditError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class ComputeCreditSettingsRow(Base):
    __tablename__ = "compute_credit_settings"
    settings_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    metering_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class ComputeCreditAccountRow(Base):
    __tablename__ = "compute_credit_accounts"
    person_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    cpu_units: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    gpu_units: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    cpu_reserved: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    gpu_reserved: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class ComputeLedgerAccountRow(Base):
    __tablename__ = "compute_ledger_accounts"
    person_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    ledger_scope: Mapped[str] = mapped_column(String(32), primary_key=True)
    cpu_units: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    gpu_units: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    cpu_reserved: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    gpu_reserved: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class ComputeLedgerMigrationRow(Base):
    __tablename__ = "compute_ledger_migrations"
    migration_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)


class ComputePoolConsentRow(Base):
    __tablename__ = "compute_pool_consents"
    machine_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)


class ComputeAccountingWeightRow(Base):
    __tablename__ = "compute_accounting_weights"
    machine_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)


class ComputeCreditReservationRow(Base):
    __tablename__ = "compute_credit_reservations"
    attempt_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    requester_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)


class ComputeCreditJournalRow(Base):
    """Append-only deltas; a unique key makes every business event idempotent."""
    __tablename__ = "compute_credit_journal"
    entry_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    person_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    attempt_id: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)


def _units(hours) -> int:
    value = Decimal(str(hours))
    if not value.is_finite() or value < 0:
        raise ValueError("credit amounts must be finite and nonnegative")
    units = int((value * UNITS_PER_HOUR).to_integral_value(rounding=ROUND_CEILING))
    if units > 9_000_000_000_000_000:
        raise ValueError("credit amount exceeds the supported bound")
    return units


def _weight(value) -> str:
    try:
        decimal = Decimal(str(value))
    except (InvalidOperation, TypeError) as exc:
        raise ValueError("invalid accounting weight") from exc
    if (not decimal.is_finite() or decimal <= 0 or decimal > 1_000_000
            or decimal.normalize().as_tuple().exponent < -6):
        raise ValueError("accounting weights must be positive finite decimals with at most six fractional digits")
    return format(decimal.normalize(), "f")


def _usage(cpus: int, gpus: int, duration_s: float, *, cpu_weight="1", gpu_weight="1") -> tuple[int, int]:
    if not isinstance(cpus, int) or isinstance(cpus, bool) or cpus < 0:
        raise ValueError("cpus must be a nonnegative integer")
    if not isinstance(gpus, int) or isinstance(gpus, bool) or gpus < 0:
        raise ValueError("gpus must be a nonnegative integer")
    duration = Decimal(str(duration_s))
    if not duration.is_finite() or duration < 0:
        raise ValueError("duration must be finite and nonnegative")
    return _units(duration * cpus * Decimal(cpu_weight) / 3600), _units(duration * gpus * Decimal(gpu_weight) / 3600)


def _hours(units: int) -> float:
    return units / UNITS_PER_HOUR


def _fingerprint(payload) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ComputeCredits:
    def __init__(self, repository):
        self.repository = repository
        tables = [ComputeCreditSettingsRow, ComputeCreditAccountRow, ComputePoolConsentRow,
                  ComputeCreditReservationRow, ComputeCreditJournalRow, PersonSubmissionPolicyRow, ComputeAccountingWeightRow,
                  ComputeLedgerAccountRow, ComputeLedgerMigrationRow]
        if not getattr(repository, "_transaction_session", lambda: None)():
            Base.metadata.create_all(repository.engine, tables=[row.__table__ for row in tables])
        # The settings row is also the PostgreSQL cross-process ledger mutex.
        with _serialized_write(repository) as session:
            if session.get(ComputeCreditSettingsRow, "global") is None:
                session.add(ComputeCreditSettingsRow(settings_id="global", metering_enabled=False))
                session.flush()
            self._settings(session)
            migration = migrate_legacy_credits(session, account_type=ComputeLedgerAccountRow,
                legacy_type=ComputeCreditAccountRow, reservation_type=ComputeCreditReservationRow,
                journal_type=ComputeCreditJournalRow, migration_type=ComputeLedgerMigrationRow,
                created_at=utc_now().isoformat())
            if migration and (migration["legacy_account_count"] or migration["legacy_journal_count"]):
                _append_audit(session, "compute_credit.legacy_isolated", "system", "compute_credits", MIGRATION_ID,
                    **migration)

    @staticmethod
    def _settings(session):
        return session.scalar(select(ComputeCreditSettingsRow)
                              .where(ComputeCreditSettingsRow.settings_id == "global").with_for_update())

    @staticmethod
    def _account(session, person_id, ledger_scope="real"):
        if ledger_scope not in SCOPES:
            raise CreditError("credit_ledger_scope_invalid")
        account = session.get(ComputeLedgerAccountRow, (person_id, ledger_scope))
        if account is None:
            account = ComputeLedgerAccountRow(person_id=person_id, ledger_scope=ledger_scope,
                cpu_units=0, gpu_units=0, cpu_reserved=0, gpu_reserved=0)
            session.add(account)
        return account

    @staticmethod
    def _journal(session, *, key, person_id, kind, attempt_id=None,
                 cpu_delta=0, gpu_delta=0, cpu_hold_delta=0, gpu_hold_delta=0, **details):
        payload = {"kind": kind, "cpu_delta_units": cpu_delta, "gpu_delta_units": gpu_delta,
                   "cpu_hold_delta_units": cpu_hold_delta, "gpu_hold_delta_units": gpu_hold_delta,
                   "cpu_weight": "1", "gpu_weight": "1", **details}
        session.add(ComputeCreditJournalRow(entry_id=key, person_id=person_id, attempt_id=attempt_id,
                                           created_at=utc_now(), payload=payload))

    def settings(self) -> dict:
        with self.repository._session() as session:
            settings = session.get(ComputeCreditSettingsRow, "global")
            return {"metering_enabled": settings.metering_enabled, "default_quota_mode": "shadow",
                    "cpu_weight": 1, "gpu_weight": 1}

    def set_metering(self, enabled: bool, *, actor_id: str) -> dict:
        _require_admin(self.repository, actor_id)
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be boolean")
        with _serialized_write(self.repository) as session:
            settings = self._settings(session)
            if settings.metering_enabled != enabled:
                settings.metering_enabled = enabled
                _append_audit(session, "compute_credit.metering_changed", actor_id, "compute_credits", "global", enabled=enabled)
        return self.settings()

    def machine_weights(self, machine_id: str) -> dict:
        with self.repository._session() as session:
            row = session.get(ComputeAccountingWeightRow, machine_id)
            return dict(row.payload) if row else {"machine_id": machine_id, "cpu_weight": "1", "gpu_weight": "1",
                                                 "source": "default"}

    def set_machine_weights(self, machine_id: str, *, cpu_weight, gpu_weight, actor_id: str) -> dict:
        _require_admin(self.repository, actor_id)
        if self.repository.get_machine(machine_id) is None:
            raise CreditError("credit_machine_not_found")
        payload = {"machine_id": machine_id, "cpu_weight": _weight(cpu_weight), "gpu_weight": _weight(gpu_weight),
                   "updated_at": utc_now().isoformat(), "source": "admin"}
        with _serialized_write(self.repository) as session:
            self._settings(session)
            row = session.get(ComputeAccountingWeightRow, machine_id) or ComputeAccountingWeightRow(machine_id=machine_id)
            row.payload = payload
            session.add(row)
            _append_audit(session, "compute_credit.machine_weights_changed", actor_id, "machine", machine_id, weights=payload)
        return payload

    def set_machine_pool_consent(self, machine_id: str, *, actor_id: str, free_idle_enabled: bool,
                                 mutual_enabled: bool = True) -> dict:
        machine = self.repository.get_machine(machine_id)
        user = self.repository.get_user(actor_id)
        if machine is None or machine.owner_user_id != actor_id or not user or not user.active:
            raise CreditError("machine_owner_consent_required")
        if not isinstance(free_idle_enabled, bool) or not isinstance(mutual_enabled, bool):
            raise ValueError("pool consent must be boolean")
        payload = {"machine_id": machine_id, "owner_user_id": actor_id,
                   "free_idle_enabled": free_idle_enabled, "mutual_enabled": mutual_enabled,
                   "consented_at": utc_now().isoformat()}
        with _serialized_write(self.repository) as session:
            self._settings(session)
            row = session.get(ComputePoolConsentRow, machine_id)
            if row is not None and all(row.payload.get(key) == payload[key] for key in
                    ("owner_user_id", "free_idle_enabled", "mutual_enabled")):
                return dict(row.payload)
            row = row or ComputePoolConsentRow(machine_id=machine_id)
            row.payload = payload
            session.add(row)
            _append_audit(session, "compute_credit.pool_consent", actor_id, "machine", machine_id, consent=payload)
        return payload

    def machine_pool_consent(self, machine_id: str) -> dict:
        with self.repository._session() as session:
            row = session.get(ComputePoolConsentRow, machine_id)
            return dict(row.payload) if row else {"machine_id": machine_id, "free_idle_enabled": False,
                                                 "mutual_enabled": True, "source": "legacy_machine_consent"}

    def balance(self, person_id: str) -> dict:
        with self.repository._session() as session:
            def amounts(scope):
                row = session.get(ComputeLedgerAccountRow, (person_id, scope))
                cpu, gpu, cpu_reserved, gpu_reserved = ((row.cpu_units, row.gpu_units, row.cpu_reserved, row.gpu_reserved)
                                                       if row else (0, 0, 0, 0))
                return {"cpu_core_hours":_hours(cpu), "gpu_device_hours":_hours(gpu),
                    "reserved_cpu_core_hours":_hours(cpu_reserved), "reserved_gpu_device_hours":_hours(gpu_reserved),
                    "available_cpu_core_hours":_hours(cpu-cpu_reserved), "available_gpu_device_hours":_hours(gpu-gpu_reserved)}
            pending = session.scalars(select(ComputeCreditReservationRow).where(
                ComputeCreditReservationRow.requester_id == person_id,
                ComputeCreditReservationRow.state == "pending_review")).all()
            ambiguous = session.scalars(select(ComputeCreditReservationRow).where(
                ComputeCreditReservationRow.requester_id == person_id,
                ComputeCreditReservationRow.payload["ledger_scope"].as_string() == "legacy_shadow")).all()
            migration = session.get(ComputeLedgerMigrationRow, MIGRATION_ID)
            mismatch = (migration.payload.get("account_journal_mismatch_person_ids", []) if migration else [])
            legacy_values = amounts("legacy_shadow")
            return {"person_id":person_id, **amounts("real"), "shadow_balance":amounts("shadow"),
                "legacy_balance":legacy_values, "pending_review_attempt_ids":[r.attempt_id for r in pending],
                "legacy_isolation":{"present":bool(ambiguous) or any(legacy_values.values()) or person_id in mismatch,
                    "automatic_conversion":False,
                    "ambiguous_attempt_ids":[r.attempt_id for r in ambiguous if r.payload.get("ledger_scope")=="legacy_shadow"],
                    "account_journal_mismatch_person_ids":[person_id] if person_id in mismatch else [],
                    "note":"旧混合账保留；无法证明正式的记录不可兑换，需管理员显式复核或授予"}}

    def adjust(self, person_id: str, *, operation_id: str, cpu_core_hours=0, gpu_device_hours=0,
               reason: str, actor_id: str) -> dict:
        """Explicit, idempotent admin bootstrap credit. Never a machine earning."""
        _require_admin(self.repository, actor_id)
        if not reason.strip() or not operation_id or len(operation_id) > 160:
            raise ValueError("an operation id and reason are required")
        if self.repository.get_user(person_id) is None:
            raise CreditError("credit_person_not_found")
        cpu, gpu = _units(cpu_core_hours), _units(gpu_device_hours)
        key = "adjust:" + operation_id
        details = {"cpu": cpu, "gpu": gpu, "reason": reason, "actor_id": actor_id}
        with _serialized_write(self.repository) as session:
            self._settings(session)
            existing = session.get(ComputeCreditJournalRow, key)
            if existing:
                if existing.person_id != person_id or existing.payload.get("request") != details:
                    raise CreditError("credit_operation_conflict")
            else:
                account = self._account(session, person_id)
                account.cpu_units += cpu
                account.gpu_units += gpu
                self._journal(session, key=key, person_id=person_id, kind="admin_adjustment",
                              cpu_delta=cpu, gpu_delta=gpu, request=details, ledger_scope="real")
                _append_audit(session, "compute_credit.adjusted", actor_id, "person", person_id,
                              operation_id=operation_id, cpu_units=cpu, gpu_units=gpu, reason=reason)
        return self.balance(person_id)

    def reserve(self, *, attempt_id: str, requester_id: str, machine_id: str, cpus: int,
                estimated_duration_s: float, gpus: int = 0, pool: Pool = "mutual",
                job_id: str | None = None, work_unit_id: str | None = None,
                actor_id: str = "dispatcher") -> dict:
        if not attempt_id or len(attempt_id) > 160 or pool not in {"mutual", "free_idle"}:
            raise ValueError("invalid attempt id or compute pool")
        cpu, gpu = _usage(cpus, gpus, estimated_duration_s)
        machine = self.repository.get_machine(machine_id)
        requester = self.repository.get_user(requester_id)
        if machine is None or requester is None or not requester.active:
            raise CreditError("credit_machine_or_person_not_found")
        request = {"attempt_id": attempt_id, "requester_id": requester_id, "machine_id": machine_id,
                   "cpus": cpus, "gpus": gpus, "estimated_cpu_units": cpu, "estimated_gpu_units": gpu,
                   "pool": pool, "job_id": job_id, "work_unit_id": work_unit_id}
        with _serialized_write(self.repository) as session:
            settings = self._settings(session)
            existing = session.get(ComputeCreditReservationRow, attempt_id)
            if existing:
                if existing.payload["request"] != request:
                    raise CreditError("credit_reservation_conflict")
                return dict(existing.payload)
            consent_row = session.get(ComputePoolConsentRow, machine_id)
            consent = consent_row.payload if consent_row else {}
            # A transfer of machine ownership invalidates previous pool consent.
            current_consent = consent.get("owner_user_id") == machine.owner_user_id
            if pool == "free_idle" and not (current_consent and consent.get("free_idle_enabled")):
                raise CreditError("free_idle_owner_consent_required")
            if pool == "mutual" and current_consent and not consent.get("mutual_enabled", True):
                raise CreditError("mutual_pool_disabled_by_owner")
            policy_row = session.get(PersonSubmissionPolicyRow, requester_id)
            quota_mode = policy_row.payload.get("quota_mode", "shadow") if policy_row else "shadow"
            enforced = settings.metering_enabled and quota_mode == "metered"
            ledger_scope = "real" if settings.metering_enabled and quota_mode in {"metered", "unlimited"} else "shadow"
            self_use = requester_id == machine.owner_user_id
            exchange = pool == "mutual" and not self_use
            weight_row = session.get(ComputeAccountingWeightRow, machine_id)
            weights = ({"cpu": weight_row.payload["cpu_weight"], "gpu": weight_row.payload["gpu_weight"]}
                       if weight_row else {"cpu": "1", "gpu": "1"})
            weighted_cpu, weighted_gpu = _usage(cpus, gpus, estimated_duration_s,
                                                cpu_weight=weights["cpu"], gpu_weight=weights["gpu"])
            hold_cpu, hold_gpu = (weighted_cpu, weighted_gpu) if exchange else (0, 0)
            account = self._account(session, requester_id, ledger_scope)
            if exchange and enforced and (
                (hold_cpu > 0 and account.cpu_units - account.cpu_reserved < hold_cpu)
                or (hold_gpu > 0 and account.gpu_units - account.gpu_reserved < hold_gpu)
            ):
                raise CreditError("insufficient_compute_credits")
            account.cpu_reserved += hold_cpu
            account.gpu_reserved += hold_gpu
            payload = {"request": request, "owner_user_id": machine.owner_user_id, "self_use": self_use,
                       "quota_mode": quota_mode, "metering_enforced": enforced, "accounting_weights": weights,
                       "ledger_scope": ledger_scope,
                       "held_cpu_units": hold_cpu, "held_gpu_units": hold_gpu, "state": "reserved",
                       "created_at": utc_now().isoformat()}
            session.add(ComputeCreditReservationRow(attempt_id=attempt_id, requester_id=requester_id,
                                                   state="reserved", payload=payload))
            self._journal(session, key="reserve:" + attempt_id, person_id=requester_id,
                          attempt_id=attempt_id, kind="reservation", cpu_hold_delta=hold_cpu,
                          gpu_hold_delta=hold_gpu, pool=pool, quota_mode=quota_mode,
                          ledger_scope=ledger_scope,
                          cpu_weight=weights["cpu"], gpu_weight=weights["gpu"])
            _append_audit(session, "compute_credit.reserved", actor_id, "attempt", attempt_id,
                          requester_id=requester_id, machine_id=machine_id, pool=pool,
                          cpu_units=hold_cpu, gpu_units=hold_gpu, metering_enforced=enforced, ledger_scope=ledger_scope)
            return payload

    def get_reservation(self, attempt_id: str) -> dict | None:
        with self.repository._session() as session:
            row = session.get(ComputeCreditReservationRow, attempt_id)
            return dict(row.payload) if row else None

    def settle(self, attempt_id: str, *, outcome: str, actual_duration_s: float | None,
               actor_id: str = "dispatcher") -> dict:
        """Finalize known outcomes; unknown evidence retains its hold for review.

        Infrastructure failures refund the whole hold and mint no supplier
        credits. Other known outcomes exchange actual usage. An enforced actual
        overrun without sufficient balance remains pending review, never mints
        an unbacked supplier payment. A retry must use its own attempt id.
        """
        known = {"completed", "scientific_input", "resource_exhaustion", "cancelled", "infrastructure"}
        if outcome not in known | {"unknown"}:
            raise ValueError("unsupported credit settlement outcome")
        if actual_duration_s is not None:
            _usage(0, 0, actual_duration_s)
        with _serialized_write(self.repository) as session:
            self._settings(session)
            row = session.get(ComputeCreditReservationRow, attempt_id)
            if row is None:
                raise CreditError("credit_reservation_not_found")
            payload = dict(row.payload)
            request = payload["request"]
            settlement_request = {"outcome": outcome, "actual_duration_s": actual_duration_s}
            if row.state == "settled":
                if payload.get("settlement_request") != settlement_request:
                    raise CreditError("credit_settlement_conflict")
                return payload
            cpu, gpu = _usage(request["cpus"], request["gpus"], actual_duration_s or 0)
            exchange = request["pool"] == "mutual" and not payload["self_use"] and outcome != "infrastructure"
            weights = payload.get("accounting_weights", {"cpu": "1", "gpu": "1"})
            weighted_cpu, weighted_gpu = _usage(request["cpus"], request["gpus"], actual_duration_s or 0,
                                                cpu_weight=weights["cpu"], gpu_weight=weights["gpu"])
            charge_cpu, charge_gpu = (weighted_cpu, weighted_gpu) if exchange else (0, 0)
            ledger_scope = payload["ledger_scope"]
            account = self._account(session, row.requester_id, ledger_scope)
            pending_reason = None
            if outcome == "unknown" or (actual_duration_s is None and outcome != "infrastructure"):
                pending_reason = "unknown_usage_or_failure"
            elif exchange and payload["metering_enforced"] and (
                (charge_cpu > 0 and account.cpu_units - account.cpu_reserved + payload["held_cpu_units"] < charge_cpu)
                or (charge_gpu > 0 and account.gpu_units - account.gpu_reserved + payload["held_gpu_units"] < charge_gpu)
            ):
                pending_reason = "actual_usage_exceeds_available_credits"
            if pending_reason:
                observation = {**settlement_request, "reason": pending_reason}
                key = "review:" + _fingerprint({"attempt_id": attempt_id, **observation})
                if session.get(ComputeCreditJournalRow, key) is None:
                    self._journal(session, key=key, person_id=row.requester_id, attempt_id=attempt_id,
                                  kind="pending_review", observation=observation, ledger_scope=ledger_scope)
                    _append_audit(session, "compute_credit.pending_review", actor_id, "attempt", attempt_id,
                                  reason=pending_reason)
                payload.update(state="pending_review", pending_review=observation)
                row.state, row.payload = "pending_review", payload
                return payload
            account.cpu_reserved -= payload["held_cpu_units"]
            account.gpu_reserved -= payload["held_gpu_units"]
            account.cpu_units -= charge_cpu
            account.gpu_units -= charge_gpu
            self._journal(session, key="settle:" + attempt_id, person_id=row.requester_id,
                          attempt_id=attempt_id, kind="settlement", cpu_delta=-charge_cpu, gpu_delta=-charge_gpu,
                          cpu_hold_delta=-payload["held_cpu_units"], gpu_hold_delta=-payload["held_gpu_units"],
                          outcome=outcome, actual_cpu_units=cpu, actual_gpu_units=gpu, pool=request["pool"],
                          ledger_scope=ledger_scope,
                          cpu_weight=weights["cpu"], gpu_weight=weights["gpu"])
            if exchange and (charge_cpu or charge_gpu):
                owner = self._account(session, payload["owner_user_id"], ledger_scope)
                owner.cpu_units += charge_cpu
                owner.gpu_units += charge_gpu
                self._journal(session, key="earn:" + attempt_id, person_id=owner.person_id,
                              attempt_id=attempt_id, kind="contribution", cpu_delta=charge_cpu, gpu_delta=charge_gpu,
                              ledger_scope=ledger_scope,
                              cpu_weight=weights["cpu"], gpu_weight=weights["gpu"])
            payload.update(state="settled", settlement_request=settlement_request,
                           charged_cpu_core_hours=_hours(charge_cpu), charged_gpu_device_hours=_hours(charge_gpu),
                           actual_cpu_core_hours=_hours(cpu), actual_gpu_device_hours=_hours(gpu),
                           settled_at=utc_now().isoformat())
            payload.pop("pending_review", None)
            row.state, row.payload = "settled", payload
            _append_audit(session, "compute_credit.settled", actor_id, "attempt", attempt_id,
                          outcome=outcome, cpu_units=charge_cpu, gpu_units=charge_gpu, pool=request["pool"], ledger_scope=ledger_scope)
            return payload

    def reserve_attempt(self, job, unit, attempt, *, pool: Pool = "mutual", actor_id: str = "dispatcher") -> dict:
        """Reserve the frozen Attempt resources before publishing its assignment.

        Use inside repository.atomic_write() with assignment persistence. Reserve
        the hard timeout rather than a forecast, so ordinary forecast error does
        not exhaust the held balance while execution continues.
        """
        if not attempt.machine_id or attempt.resolved_resources is None:
            raise CreditError("credit_attempt_resources_not_frozen")
        resources = attempt.resolved_resources.resources
        return self.reserve(attempt_id=attempt.attempt_id, requester_id=job.user_id,
                            machine_id=attempt.machine_id, cpus=resources.cpus, gpus=resources.gpus,
                            estimated_duration_s=job.timeout_s, pool=pool, job_id=job.job_id,
                            work_unit_id=unit.work_unit_id, actor_id=actor_id)

    def settle_attempt(self, job, unit, attempt, *, actual_duration_s: float | None = None,
                       outcome: str | None = None, actor_id: str = "dispatcher") -> dict | None:
        """Consume terminal Attempt evidence; never backfill historical work.

        An execution-end observation wins over collection timestamps. The caller
        may supply a measured duration (completion receipt). Unknown timing or
        failure attribution stays pending; a missing reservation is untouched.
        """
        reservation = self.get_reservation(attempt.attempt_id)
        if reservation is None:
            return None
        if reservation["request"]["job_id"] not in {None, job.job_id}:
            raise CreditError("credit_attempt_job_mismatch")
        if reservation["request"]["work_unit_id"] not in {None, unit.work_unit_id}:
            raise CreditError("credit_attempt_unit_mismatch")
        if reservation["state"] == "settled":
            return reservation
        if outcome is None:
            if attempt.state == "completed":
                outcome = "completed"
            elif attempt.state in {"failed", "cancelled", "abandoned"}:
                failure_class = getattr(attempt.failure_class, "value", attempt.failure_class)
                outcome = failure_class or ("cancelled" if attempt.state == "cancelled" else "unknown")
            else:
                return None
        if actual_duration_s is None:
            measured = getattr(unit, "actual_duration_s", None)
            attempts = getattr(unit, "attempts", [])
            if (outcome == "completed" and attempts and attempts[-1].attempt_id == attempt.attempt_id
                    and measured is not None and math.isfinite(measured) and measured > 0):
                actual_duration_s = measured
        if actual_duration_s is None:
            end = attempt.execution_end_observed_at or attempt.finished_at
            if end is not None and attempt.started_at is not None:
                actual_duration_s = max(0.0, (end - attempt.started_at).total_seconds())
            elif not attempt.execution_started and attempt.started_at is None and outcome == "cancelled":
                actual_duration_s = 0.0
        return self.settle(attempt.attempt_id, outcome=outcome, actual_duration_s=actual_duration_s, actor_id=actor_id)

    def journal(self, person_id: str, *, limit: int = 100) -> list[dict]:
        if not 1 <= limit <= 1000:
            raise ValueError("journal limit must be between 1 and 1000")
        with self.repository._session() as session:
            rows = session.scalars(select(ComputeCreditJournalRow)
                .where(ComputeCreditJournalRow.person_id == person_id)
                .order_by(ComputeCreditJournalRow.created_at, ComputeCreditJournalRow.entry_id).limit(limit)).all()
            attempt_ids = {row.attempt_id for row in rows if row.attempt_id}
            scopes = {row.attempt_id:row.payload.get("ledger_scope", "legacy_shadow")
                for row in session.scalars(select(ComputeCreditReservationRow).where(
                    ComputeCreditReservationRow.attempt_id.in_(attempt_ids)))} if attempt_ids else {}
            return [{"entry_id": r.entry_id, "attempt_id": r.attempt_id,
                     "created_at": r.created_at.isoformat(), **r.payload,
                     "ledger_scope":r.payload.get("ledger_scope") or (
                         "real" if r.payload.get("kind")=="admin_adjustment" else scopes.get(r.attempt_id, "legacy_shadow"))}
                    for r in rows]
