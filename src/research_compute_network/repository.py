"""SQL-backed operational metadata repository.

The repository deliberately stores manifests and policy metadata, not research
artifact bytes. SQLite is used for the pilot; the SQLAlchemy boundary keeps the
schema portable to PostgreSQL when the control plane is extracted.
"""

from __future__ import annotations

import copy
from functools import wraps
from contextlib import contextmanager, nullcontext
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta, timezone
import json
import hashlib
import zlib
import math
from pathlib import Path
import sqlite3
import statistics
import threading
import time
from typing import Any, TypeVar

from sqlalchemy import JSON, Boolean, DateTime, Index, Integer, LargeBinary, String, case, create_engine, delete, event, false, func, inspect, or_, select, text, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from .connection_health import merge_channel_evidence
from .failure_diagnostics import sanitize_failure_text
from .models import (
    AlertStatus,
    AlertRecord,
    ApprovalRecord,
    AdminOperationTicket,
    ApiTokenRecord,
    ArtifactManifest,
    AuditEvent,
    BreakGlassConfig,
    ControlOperationRun,
    DatasetMetadata,
    DispatchReservation,
    DispatcherControlTicket,
    DispatcherLease,
    DispatcherStatus,
    DemoCleanupPreview,
    ExecutionProfile,
    EnrollmentRecord,
    FeatureSettings,
    JobEnvelope,
    JobStatus,
    MachineAgentCredential,
    MachineCommandResult,
    MachineControlTicket,
    MachinePolicy,
    MachineState,
    MachineExecutionConfig,
    MachinePreflightRun,
    MachineOperationalStatus,
    ChannelObservation,
    MetricSample,
    OriginImportReceipt,
    PartitionPlan,
    PressureOverrideTicket,
    ProjectRegistrationRequest,
    ProjectGrant,
    OriginAdapterRegistration,
    RemoteRunRecord,
    SshAcceptanceRun,
    SolverCompatibilityApproval,
    TelemetryState,
    UserAccount,
    WorkUnitStatus,
    derived_job_status,
    job_activity_state,
)
from .operational import age_machine_operational_status
from .read_models import (
    READ_MODEL_VERSION, TERMINAL_ATTEMPT_STATES, AttemptReadRow,
    JobReadRow, JobVisibility, ReadModelBase, ReadRevisionRow, UnitReadRow, replace_job_read_model,
)


def _aware_datetime(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class Base(DeclarativeBase):
    pass


class MemberInvitationOperationRow(Base):
    """Durable issuance identity/cancellation; never stores a delivery secret."""
    __tablename__ = "member_invitation_operations"
    operation_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(160), nullable=False)
    request_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enrollment_id: Mapped[str | None] = mapped_column(String(160), nullable=True, unique=True)
    cancelled: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SubmissionOperationRow(Base):
    """Permanent operation receipts, including the original terminal Job ID."""
    __tablename__ = "submission_operations"
    operation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    job_id: Mapped[str | None] = mapped_column(String(160), nullable=True, unique=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class MemberRetirementRow(Base):
    """Owner drain intent and immutable original-node withdrawal evidence."""
    __tablename__ = "member_retirement_operations"
    machine_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    operation_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class _BorrowedSubmissionSession:
    """Join repository helpers to one caller-owned submission transaction."""
    def __init__(self, session):
        self.session = session

    def __getattr__(self, name):
        return getattr(self.session, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def commit(self):
        # Only the transaction owner may commit; nested helpers may make
        # pending writes visible to subsequent reads in the same transaction.
        self.session.flush()

    @contextmanager
    def begin(self):
        yield self
        self.session.flush()



class ProfileRow(Base):
    __tablename__ = "execution_profiles"
    profile_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class UserRow(Base):
    __tablename__ = "users"
    user_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class TokenRow(Base):
    __tablename__ = "api_tokens"
    token_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class MachineCredentialRow(Base):
    __tablename__ = "machine_agent_credentials"
    credential_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    machine_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ProjectGrantRow(Base):
    __tablename__ = "project_grants"
    project_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    approved: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class MachineRow(Base):
    __tablename__ = "machines"
    machine_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    owner_user_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class PolicyRow(Base):
    __tablename__ = "machine_policies"
    machine_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ApprovalRow(Base):
    __tablename__ = "approvals"
    approval_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    machine_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ProjectRegistrationRow(Base):
    __tablename__ = "project_registrations"
    registration_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class OriginAdapterRow(Base):
    __tablename__ = "origin_adapters"
    adapter_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class SolverApprovalRow(Base):
    __tablename__ = "solver_compatibility_approvals"
    approval_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class PartitionPlanRow(Base):
    __tablename__ = "partition_plans"
    plan_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class StorageBlobRow(Base):
    """Content-addressed compressed metadata payloads (never scientific artifacts)."""
    __tablename__ = "storage_blobs"
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    codec: Mapped[str] = mapped_column(String(32), nullable=False)
    original_size: Mapped[int] = mapped_column(Integer, nullable=False)
    compressed_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reference_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class JobRow(Base):
    __tablename__ = "jobs"
    job_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    user_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    operational_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    __table_args__ = (
        Index("ix_jobs_created_job", "created_at", "job_id"),
        Index("ix_jobs_project_created_job", "project_id", "created_at", "job_id"),
        Index("ix_jobs_user_created_job", "user_id", "created_at", "job_id"),
    )


class DispatcherLeaseRow(Base):
    __tablename__ = "dispatcher_leases"
    lease_name: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)


class DispatcherStatusRow(Base):
    __tablename__ = "dispatcher_status"
    status_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class DispatchReservationRow(Base):
    __tablename__ = "dispatch_reservations"
    reservation_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    active_key: Mapped[str | None] = mapped_column(
        String(200), nullable=True, unique=True, index=True
    )
    machine_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    job_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    work_unit_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class EnrollmentRow(Base):
    __tablename__ = "node_enrollments"
    enrollment_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    owner_user_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class EventRow(Base):
    __tablename__ = "audit_events"
    event_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    subject_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    sequence: Mapped[int | None] = mapped_column(Integer, nullable=True, unique=True, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class EventSequenceRow(Base):
    __tablename__ = "audit_event_sequence"
    sequence_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    next_sequence: Mapped[int] = mapped_column(Integer, nullable=False)


class ArtifactRow(Base):
    __tablename__ = "artifact_manifests"
    work_unit_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    job_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class MetricSampleRow(Base):
    __tablename__ = "machine_metric_samples"
    sample_id: Mapped[str] = mapped_column(String(240), primary_key=True)
    machine_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    sample_kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class FeatureSettingsRow(Base):
    __tablename__ = "feature_settings"
    settings_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class MachineExecutionConfigRow(Base):
    __tablename__ = "machine_execution_configs"
    machine_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class MachineOperationalStatusRow(Base):
    __tablename__ = "machine_operational_status"
    machine_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class OriginImportReceiptRow(Base):
    __tablename__ = "origin_import_receipts"
    job_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    dataset_id: Mapped[str] = mapped_column(String(240), nullable=False, index=True)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class PressureOverrideTicketRow(Base):
    __tablename__ = "pressure_override_tickets"
    ticket_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    machine_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class AdminOperationTicketRow(Base):
    __tablename__ = "admin_operation_tickets"
    ticket_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    job_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class MachineControlTicketRow(Base):
    __tablename__ = "machine_control_tickets"
    ticket_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class ControlOperationRunRow(Base):
    __tablename__ = "control_operation_runs"
    operation_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    ticket_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class MachineCommandResultRow(Base):
    __tablename__ = "machine_command_results"
    command_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    machine_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class DispatcherControlTicketRow(Base):
    __tablename__ = "dispatcher_control_tickets"
    ticket_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class BreakGlassConfigRow(Base):
    __tablename__ = "break_glass_config"
    config_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class AlertRow(Base):
    __tablename__ = "alerts"
    alert_id: Mapped[str] = mapped_column(String(240), primary_key=True)
    severity: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    subject_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class DatasetMetadataRow(Base):
    __tablename__ = "dataset_metadata"
    dataset_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class RemoteRunRow(Base):
    __tablename__ = "remote_runs"
    external_run_id: Mapped[str] = mapped_column(String(240), primary_key=True)
    machine_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    work_unit_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class SshAcceptanceRow(Base):
    __tablename__ = "ssh_acceptance_runs"
    run_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class MachinePreflightRow(Base):
    __tablename__ = "machine_preflight_runs"
    run_id: Mapped[str] = mapped_column(String(160), primary_key=True)
    machine_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


ModelT = TypeVar("ModelT")


class RevisionConflictError(RuntimeError):
    """The caller attempted to persist a stale aggregate revision."""


class PolicyRevisionConflict(ValueError):
    """The caller's raw policy snapshot no longer matches the stored policy."""


def _validate_policy_payload_sha256(value) -> None:
    if (not isinstance(value, str) or len(value) != 64
            or any(character not in '0123456789abcdef' for character in value)):
        raise PolicyRevisionConflict('machine policy revision must be 64 lowercase hexadecimal characters')


def _payload(model: Any) -> dict[str, Any]:
    return model.model_dump(mode="json")


_BLOB_MARKER = "$rcn_storage_blob"
_BLOB_CODEC = "zlib-json-v1"


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _blob_ref(payload: Any) -> dict[str, Any]:
    raw = _canonical_json(payload)
    return {_BLOB_MARKER: {"sha256": hashlib.sha256(raw).hexdigest(), "codec": _BLOB_CODEC}}


def _hydrate_payload(
    session: Session,
    payload: Any,
    *,
    expand_blobs: bool = True,
) -> Any:
    """Expand blob references recursively; optionally keep references opaque.

    Dispatcher recovery and other metadata-only scans do not need the large
    scientific item payloads.  Keeping the marker in those paths avoids
    decompressing every item while preserving the legacy/full-read contract.
    """
    if isinstance(payload, dict) and set(payload) == {_BLOB_MARKER}:
        if not expand_blobs:
            return payload
        reference = payload[_BLOB_MARKER]
        digest = str(reference.get("sha256") or "")
        row = session.get(StorageBlobRow, digest)
        if row is None:
            raise RuntimeError(f"storage blob is missing: {digest}")
        raw = zlib.decompress(row.compressed_payload)
        value = json.loads(raw.decode("utf-8"))
        return _hydrate_payload(session, value, expand_blobs=expand_blobs)
    if isinstance(payload, dict):
        return {
            key: _hydrate_payload(session, value, expand_blobs=expand_blobs)
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [
            _hydrate_payload(session, value, expand_blobs=expand_blobs)
            for value in payload
        ]
    return payload


def _store_blob_payload(session: Session, payload: Any) -> dict[str, Any]:
    # A blob is deliberately self-contained. This also upgrades an aggregate
    # read through the legacy per-item format without creating nested refs that
    # could later be orphaned by reference-count reconciliation.
    self_contained = _hydrate_payload(session, payload)
    raw = _canonical_json(self_contained)
    digest = hashlib.sha256(raw).hexdigest()
    row = session.get(StorageBlobRow, digest)
    if row is None:
        row = StorageBlobRow(
            sha256=digest,
            codec=_BLOB_CODEC,
            original_size=len(raw),
            compressed_payload=zlib.compress(raw, level=9),
            created_at=datetime.now(timezone.utc),
            reference_count=0,
        )
        session.add(row)
    # Reference counts are reconciled once per aggregate write below.  Do not
    # increment here: a read/modify/write of an unchanged Job would otherwise
    # inflate the count and create a needless SQLite write conflict.
    return _blob_ref(self_contained)


def _blob_digest_counts(value: Any) -> dict[str, int]:
    """Count content-addressed references in a stored aggregate payload."""
    counts: dict[str, int] = {}
    if isinstance(value, dict):
        if set(value) == {_BLOB_MARKER}:
            reference = value.get(_BLOB_MARKER)
            if isinstance(reference, dict):
                digest = str(reference.get("sha256") or "")
                if digest:
                    counts[digest] = 1
            return counts
        values = value.values()
    elif isinstance(value, list):
        values = value
    else:
        return counts
    for item in values:
        for digest, count in _blob_digest_counts(item).items():
            counts[digest] = counts.get(digest, 0) + count
    return counts


def _reconcile_blob_reference_counts(
    session: Session,
    before: Any,
    after: Any,
) -> None:
    """Apply only the reference-count delta for one aggregate replacement."""
    previous = _blob_digest_counts(before)
    current = _blob_digest_counts(after)
    for digest in previous.keys() | current.keys():
        delta = current.get(digest, 0) - previous.get(digest, 0)
        if not delta:
            continue
        row = session.get(StorageBlobRow, digest)
        if row is None:
            # A malformed legacy marker should not make an operational write
            # fabricate a blob. Full reads still report the missing blob.
            continue
        row.reference_count = max(0, int(row.reference_count or 0) + delta)


def _compact_declarative_items(session: Session, value: Any) -> Any:
    """Store each complete scientific item list as one immutable blob.

    The outer list is the expensive repeated structure in PartitionPlan and
    Job JSON. Keeping it as one compressed value avoids thousands of marker
    dictionaries while operational attempt state remains inline and queryable.
    """
    if isinstance(value, list):
        return [_compact_declarative_items(session, item) for item in value]
    if not isinstance(value, dict):
        return value
    if set(value) == {_BLOB_MARKER}:
        return value
    compacted: dict[str, Any] = {}
    for key, item in value.items():
        if key == "items" and (
            isinstance(item, list)
            or (isinstance(item, dict) and set(item) == {_BLOB_MARKER})
        ):
            hydrated_items = _hydrate_payload(session, item)
            if isinstance(hydrated_items, list):
                compacted[key] = _store_blob_payload(session, hydrated_items)
                continue
        compacted[key] = _compact_declarative_items(session, item)
    return compacted


_OPERATIONAL_JOB_EXCLUDED_FIELDS = {
    "input_manifest",
    "template_parameter_evidence",
    "work_units",
}
_OPERATIONAL_UNIT_EXCLUDED_FIELDS = {"payload", "atomic_item_ids"}

_RUNS_JOB_FIELDS = {
    "schema_version",
    "job_id",
    "origin_submitter_id",
    "origin_adapter_id",
    "user_id",
    "project_id",
    "execution_profile_id",
    "campaign_id",
    "campaign_task_id",
    "recipe_kind",
    "study_kind",
    "template_role",
    "template_sha256",
    "planning_warnings",
    "request_hash",
    "partition_plan_id",
    "atomic_item_count",
    "solver_approval_id",
    "solver_compatibility_fingerprint",
    "solver_policy",
    "resource_mode",
    "priority",
    "effective_priority",
    "priority_ceiling_snapshot",
    "record_class",
    "status",
    "revision",
    "last_scheduled_at",
    "created_at",
    "updated_at",
}
_RUNS_UNIT_FIELDS = {
    "schema_version",
    "work_unit_id",
    "ordinal",
    "expected_duration_s",
    "resources",
    "required_capabilities",
    "allowed_solver_variants",
    "solver_policy",
    "resource_mode",
    "solver_approval_id",
    "preferred_machine_id",
    "required_machine_id",
    "status",
    "assigned_machine_id",
    "actual_duration_s",
    "progress_percent",
    "completed_items",
    "total_items",
    "eta_s",
    "progress_message",
    "failure_reason",
    "dispatch_failure_count",
    "dispatch_not_before_at",
    "attempt_count",
    "max_attempts",
    "atomic_item_count",
}


def _mesh_policy_from_unit_payloads(units: Iterable[Any]) -> Any:
    """Extract optional display metadata without requiring it for scheduling."""
    for unit in units:
        unit_payload = unit.payload if hasattr(unit, "payload") else unit.get("payload", {})
        if not isinstance(unit_payload, dict):
            continue
        items = unit_payload.get("items")
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("payload"), dict):
                continue
            payload = item["payload"]
            if set(payload) == {_BLOB_MARKER}:
                continue
            study = payload.get("study") if isinstance(payload.get("study"), dict) else {}
            recipe = (
                payload.get("recipe_config")
                if isinstance(payload.get("recipe_config"), dict)
                else {}
            )
            mesh_policy = study.get("mesh_policy") or recipe.get("mesh_policy")
            if mesh_policy is not None:
                return copy.deepcopy(mesh_policy)
    return None


def _job_operational_projection(
    job: JobEnvelope,
    *,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the small mutable half of a Job aggregate."""
    projection = job.model_dump(
        mode="json",
        exclude=_OPERATIONAL_JOB_EXCLUDED_FIELDS,
    )
    projection["projection_version"] = 1
    # Atomic identifiers belong to the immutable scientific half and are not
    # stored here. When this projection is rebuilt from a scheduler snapshot
    # that intentionally carries empty identifier lists, the previous count is
    # authoritative; recomputing from the empty list would publish 0 and break
    # every progress denominator downstream.
    if projection.get("atomic_item_count") is None and previous is not None:
        projection["atomic_item_count"] = copy.deepcopy(
            previous.get("atomic_item_count")
        )
    projection["work_units"] = []
    for unit in job.work_units:
        compact = unit.model_dump(
            mode="json",
            exclude=_OPERATIONAL_UNIT_EXCLUDED_FIELDS,
        )
        item_count = len(unit.atomic_item_ids)
        if not item_count:
            previous_unit = next(
                (
                    candidate
                    for candidate in (previous or {}).get("work_units") or []
                    if isinstance(candidate, dict)
                    and candidate.get("work_unit_id") == unit.work_unit_id
                ),
                None,
            )
            item_count = int(
                (previous_unit or {}).get("atomic_item_count")
                or compact.get("total_items")
                or 0
            )
        compact["atomic_item_count"] = item_count
        projection["work_units"].append(compact)
    mesh_policy = _mesh_policy_from_unit_payloads(job.work_units)
    if mesh_policy is None and previous is not None:
        mesh_policy = copy.deepcopy(previous.get("mesh_policy"))
    projection["mesh_policy"] = mesh_policy
    return projection


def _stored_job_operational_projection(payload: dict[str, Any]) -> dict[str, Any]:
    """Backfill a projection from stored JSON without expanding blob values."""
    projection = {
        key: copy.deepcopy(value)
        for key, value in payload.items()
        if key not in _OPERATIONAL_JOB_EXCLUDED_FIELDS
    }
    projection["projection_version"] = 1
    projection["mesh_policy"] = _mesh_policy_from_unit_payloads(
        payload.get("work_units") or []
    )
    projection["work_units"] = []
    for unit in payload.get("work_units") or []:
        if not isinstance(unit, dict):
            continue
        compact = {
            key: copy.deepcopy(value)
            for key, value in unit.items()
            if key not in _OPERATIONAL_UNIT_EXCLUDED_FIELDS
        }
        compact["atomic_item_count"] = (
            len(unit.get("atomic_item_ids") or [])
            or int(unit.get("total_items") or 0)
        )
        projection["work_units"].append(compact)
    return projection


def _overlay_job_operational_payload(
    scientific_payload: dict[str, Any],
    operational_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    """Overlay mutable state while keeping the scientific payload untouched."""
    if not operational_payload:
        return scientific_payload
    merged = dict(scientific_payload)
    for key, value in operational_payload.items():
        if key not in {"projection_version", "mesh_policy", "work_units"}:
            merged[key] = value
    operational_units = {
        str(unit.get("work_unit_id")): unit
        for unit in operational_payload.get("work_units") or []
        if isinstance(unit, dict) and unit.get("work_unit_id")
    }
    merged_units: list[dict[str, Any]] = []
    for scientific_unit in scientific_payload.get("work_units") or []:
        if not isinstance(scientific_unit, dict):
            continue
        merged_unit = dict(scientific_unit)
        operational_unit = operational_units.get(str(scientific_unit.get("work_unit_id")))
        if operational_unit is not None:
            for key, value in operational_unit.items():
                if key != "atomic_item_count":
                    merged_unit[key] = value
        merged_units.append(merged_unit)
    merged["work_units"] = merged_units
    return merged


def _operational_projection_to_job(projection: dict[str, Any]) -> JobEnvelope:
    """Create an internal scheduler snapshot with no scientific item bytes."""
    payload = {
        key: copy.deepcopy(value)
        for key, value in projection.items()
        if key not in {"projection_version", "mesh_policy"}
    }
    # Atomic identifiers belong to the immutable scientific half. They are not
    # needed for placement/reconciliation and would violate aggregate coverage
    # validation when omitted, so the internal snapshot leaves the total open.
    payload["atomic_item_count"] = None
    units: list[dict[str, Any]] = []
    for unit in payload.get("work_units") or []:
        if not isinstance(unit, dict):
            continue
        compact = dict(unit)
        atomic_item_count = int(compact.pop("atomic_item_count", 0) or 0)
        if compact.get("total_items") is None and atomic_item_count:
            compact["total_items"] = atomic_item_count
        compact["payload"] = {}
        compact["atomic_item_ids"] = []
        units.append(compact)
    payload["work_units"] = units
    return JobEnvelope.model_validate(payload)


def _percentile(values: list[float], percentile: float) -> float:
    """Return an interpolated percentile for a small operational sample."""
    ordered = sorted(max(0.0, float(value)) for value in values)
    if not ordered:
        raise ValueError("percentile requires at least one value")
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _decorate_job_summary(
    summary: dict[str, Any],
    historical_durations: Iterable[float] | None = None,
    fleet_supply: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary["recorded_status"] = summary["status"]
    units = summary.get("work_units", [])
    unit_statuses = {unit.get("status") for unit in units}
    reconciliation_states = {"reconcile_pending", "uncertain", "cancel_pending"}
    reconciliation_units = [
        unit for unit in units
        if unit.get("status") not in {"completed", "cancelled", "failed_terminal"}
        and (unit.get("status") in reconciliation_states or
             (unit.get("attempts") or [{}])[-1].get("state") in reconciliation_states)
    ]
    reconciliation_payload_ids = {id(unit) for unit in reconciliation_units}
    summary["reconciliation_unit_count"] = len(reconciliation_units)
    summary["reconciliation_machine_ids"] = sorted({
        str((unit.get("attempts") or [{}])[-1]["machine_id"])
        for unit in reconciliation_units
        if (unit.get("attempts") or [{}])[-1].get("machine_id")
    })
    summary["eta_blocked_reason"] = "awaiting_reconciliation" if reconciliation_units else None
    active_states = {"assigned", "running", "reconcile_pending", "collecting"}
    waiting_states = {"queued", "prepared", "staged"}
    retryable = any(
        unit.get("status") == "failed_retriable"
        and int(unit.get("attempt_count", 0)) < int(unit.get("max_attempts", 0))
        and unit.get("attempts")
        and unit["attempts"][-1].get("state") == "failed"
        and unit["attempts"][-1].get("failure_class") in {
            "infrastructure",
            "resource_exhaustion",
        }
        for unit in units
    )
    if unit_statuses.intersection(active_states):
        status = "running"
    elif summary["recorded_status"] in {"awaiting_approval", "awaiting_environment", "blocked"} and unit_statuses.issubset(waiting_states):
        status = summary["recorded_status"]
    elif "queued" in unit_statuses:
        status = "queued"
    elif retryable:
        status = "failed_retriable"
    elif units and unit_statuses == {"completed"}:
        status = "completed"
    elif "cancelled" in unit_statuses:
        status = "cancelled"
    elif units:
        status = "failed_terminal"
    else:
        status = summary["recorded_status"]
    summary["status"] = status
    summary["activity_state"] = {
        "running": "active",
        "queued": "queued",
        "failed_retriable": "recoverable",
        "failed_terminal": "history",
        "completed": "history",
        "cancelled": "history",
        "awaiting_approval": "queued",
        "awaiting_environment": "queued",
        "blocked": "needs_attention",
    }.get(status, "needs_attention")
    for unit in units:
        attempts = unit.get("attempts") or []
        latest = attempts[-1] if attempts else None
        recoverable = bool(
            unit.get("status") == "failed_terminal"
            and latest
            and int(unit.get("max_attempts", 0)) < 10
            and latest.get("failure_class") == "infrastructure"
            and not any(attempt.get("external_run_id") for attempt in attempts)
        )
        unit["recovery_allowed"] = recoverable
        if recoverable:
            unit["recovery_reason"] = "终止前基础设施失败，未跨越远端运行边界，可在部署恢复后重试"
        unit.setdefault(
            "activity_state",
            {
                "reconcile_pending": "reconcile_pending",
                "failed_retriable": "failed",
                "failed_terminal": "failed",
            }.get(unit.get("status"), unit.get("status")),
        )
        if id(unit) in reconciliation_payload_ids:
            unit["activity_state"] = "reconcile_pending"
    completed_items = sum(
        int(
            unit.get("completed_items")
            or (
                unit.get("atomic_item_count")
                or len(unit.get("atomic_item_ids") or [])
                if unit.get("status") == "completed"
                else 0
            )
        )
        for unit in units
    )
    total_items = sum(
        int(
            unit.get("total_items")
            or unit.get("atomic_item_count")
            or len(unit.get("atomic_item_ids") or [])
            or 0
        )
        for unit in units
    )
    attempt_states = {
        (unit.get("attempts") or [{}])[-1].get("state")
        for unit in units
        if unit.get("attempts")
    }
    if reconciliation_units:
        phase = "reconcile_pending"
    elif units and all(unit.get("status") == "completed" for unit in units):
        phase = "completed"
    elif any(unit.get("status") == "collecting" for unit in units):
        phase = "collecting"
    elif "cancel_pending" in attempt_states:
        phase = "cancel_pending"
    elif any(unit.get("status") == "running" for unit in units):
        phase = "running"
    elif any(unit.get("status") == "assigned" for unit in units):
        phase = "assigned"
    elif any(unit.get("activity_state") == "prepared" for unit in units):
        phase = "prepared"
    elif status == "awaiting_approval" or any(unit.get("status") == "queued" for unit in units):
        phase = "queued"
    else:
        phase = status
    summary["activity_phase"] = phase
    summary["completed_items"] = completed_items
    summary["total_items"] = total_items or summary.get("atomic_item_count") or len(units)

    now = datetime.now(timezone.utc)

    def parse_timestamp(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    def positive_number(value: Any) -> float | None:
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return number if math.isfinite(number) and number > 0 else None

    event_times = [parse_timestamp(summary.get("updated_at")), parse_timestamp(summary.get("created_at"))]
    for unit in units:
        event_times.extend(
            parse_timestamp(unit.get(key))
            for key in ("updated_at", "last_event_at")
        )
        for attempt in (unit.get("attempts") or []):
            event_times.extend(
                parse_timestamp(attempt.get(key))
                for key in ("last_observed_at", "finished_at", "started_at", "collected_at")
            )
    event_times = [value for value in event_times if value is not None]
    last_event = max(event_times) if event_times else None
    summary["last_event_at"] = last_event.isoformat() if last_event else None
    active_starts: list[datetime] = []
    attempt_starts: list[datetime] = []
    completed_duration = 0.0
    unit_eta: list[float] = []
    completed_durations: list[float] = []
    completion_times: list[datetime] = []
    for unit in units:
        duration = unit.get("actual_duration_s")
        if duration is not None and unit.get("status") == "completed":
            # Zero is a finalization placeholder, not a measured solve time.
            measured = positive_number(duration)
            if measured is not None:
                completed_duration += measured
                completed_durations.append(measured)
        if unit.get("status") == "completed":
            finished = None
            for attempt_record in reversed(unit.get("attempts") or []):
                finished = parse_timestamp(attempt_record.get("finished_at")) or (
                    parse_timestamp(attempt_record.get("collected_at"))
                )
                if finished is not None:
                    break
            if finished is None:
                finished = parse_timestamp(unit.get("updated_at"))
            if finished is not None:
                completion_times.append(finished)
        latest = (unit.get("attempts") or [{}])[-1]
        worker_execution = unit.get("status") == "running" and latest.get("state") in {None, "running"}
        # Compact production Attempts declare last_observed_at, including a
        # missing observation. Older synthetic/legacy DTOs omit this field.
        # Keep that legacy contract, but never accept an explicitly stale,
        # malformed, missing, or future worker observation as live evidence.
        if worker_execution and "last_observed_at" in latest:
            observed = parse_timestamp(latest["last_observed_at"])
            fresh = observed is not None and -5 <= (now - observed).total_seconds() <= 120
            if not fresh:
                worker_execution = False
                if not summary["eta_blocked_reason"]:
                    summary["eta_blocked_reason"] = "stale_worker_observation"
        if unit.get("eta_s") is not None:
            eta_value = positive_number(unit["eta_s"]) if worker_execution else None
            # Workers commonly publish 0 while crossing into finalization.
            # It is not a remaining-time estimate and must not create a
            # misleading lower bound of zero for a still-active Job.
            if eta_value is not None:
                unit_eta.append(eta_value)
            else:
                # This decorates a response payload, never the persisted Unit.
                unit["eta_s"] = None
        for attempt_record in unit.get("attempts") or []:
            parsed_start = parse_timestamp(attempt_record.get("started_at"))
            if parsed_start is not None:
                attempt_starts.append(parsed_start)
        attempt = (unit.get("attempts") or [])[-1:]
        if (attempt
                and unit.get("status") in {"assigned", "running", "collecting", "reconcile_pending"}
                and attempt[0].get("state") not in {"completed", "failed", "cancelled", "abandoned"}):
            started = attempt[0].get("started_at")
            if started:
                parsed = parse_timestamp(started)
                if parsed is not None:
                    active_starts.append(parsed)
    if active_starts:
        phase_started = min(active_starts)
        summary["phase_started_at"] = phase_started.isoformat()
        summary["phase_elapsed_seconds"] = max(0.0, (now - phase_started).total_seconds())
    else:
        summary["phase_started_at"] = None
        summary["phase_elapsed_seconds"] = 0.0
    if active_starts and attempt_starts:
        summary["total_elapsed_seconds"] = max(
            0.0, (now - min(attempt_starts)).total_seconds()
        )
    else:
        summary["total_elapsed_seconds"] = completed_duration
    eta_active_phases = {"assigned", "running", "collecting"}
    remaining_units = max(
        0,
        len(units) - sum(unit.get("status") == "completed" for unit in units),
    )
    active_parallelism = max(
        1,
        sum(
            unit.get("status") in {"assigned", "running", "collecting"}
            for unit in units
        ),
    )
    queued_units = [unit for unit in units if unit.get("status") in {"queued", "prepared", "staged"}]
    queued_unit_count = len(queued_units)
    # History is relevant only to a live ETA. Validating thousands of profile
    # samples for every completed Job made a history page cost page_size times
    # the timing-history size even though those Jobs never publish an ETA.
    history = []
    if not summary["eta_blocked_reason"] and phase in eta_active_phases:
        history = completed_durations if len(completed_durations) >= 3 else [
            *completed_durations,
            *(historical_durations or []),
        ]
        history = [number for value in history if (number := positive_number(value)) is not None]
    summary["eta_updated_at"] = None
    summary["eta_lower_seconds"] = None
    summary["eta_upper_seconds"] = None
    summary["eta_active_seconds"] = None
    summary["eta_queued_seconds"] = None
    if summary["eta_blocked_reason"]:
        summary["eta_seconds"] = None
        summary["eta_confidence"] = "unknown"
        summary["eta_basis"] = (
            "unfinished Attempts await reconciliation; completion time is unknown"
            if reconciliation_units else "worker observation is not fresh; completion time is unknown"
        )
    elif phase not in eta_active_phases:
        summary["eta_seconds"] = None
        summary["eta_confidence"] = "unknown"
        summary["eta_basis"] = f"ETA paused while activity phase is {phase}"
    elif unit_eta:
        # Worker ETAs describe concurrent Units. The Job completes when the
        # slowest active Unit completes, not after their estimates are summed.
        active_eta = max(unit_eta)
        summary["eta_active_seconds"] = active_eta
        queued_estimate = None
        if queued_unit_count:
            queued_durations = [
                number
                for unit in queued_units
                if (number := positive_number(unit.get("expected_duration_s"))) is not None
            ]
            per_unit = statistics.median(history) if history else (
                statistics.median(queued_durations) if queued_durations else None
            )
            if per_unit is not None:
                queued_batches = math.ceil(queued_unit_count / active_parallelism)
                queued_estimate = per_unit * queued_batches
                summary["eta_queued_seconds"] = queued_estimate
        summary["eta_seconds"] = active_eta + (queued_estimate or 0.0)
        summary["eta_lower_seconds"] = min(unit_eta) + (queued_estimate or 0.0)
        summary["eta_upper_seconds"] = max(unit_eta) + (queued_estimate or 0.0)
        summary["eta_confidence"] = "worker" if queued_estimate is None else (
            "high" if len(history) >= 20 else "medium" if len(history) >= 5 else "low"
        )
        summary["eta_basis"] = (
            f"{len(unit_eta)} concurrent worker estimates"
            + (f" plus {queued_unit_count} queued units in {math.ceil(queued_unit_count / active_parallelism)} estimated batches"
               if queued_estimate is not None else "")
        )
    elif history and remaining_units:
        batches = math.ceil(remaining_units / active_parallelism)
        median = statistics.median(history) * batches
        lower = _percentile(history, 0.25) * batches
        upper = _percentile(history, 0.75) * batches
        summary["eta_seconds"] = median
        summary["eta_lower_seconds"] = lower
        summary["eta_upper_seconds"] = max(lower, upper)
        summary["eta_queued_seconds"] = summary["eta_seconds"]
        summary["eta_confidence"] = (
            "high" if len(history) >= 20 else "medium" if len(history) >= 5 else "low"
        )
        summary["eta_basis"] = (
            f"median and interquartile range from {len(history)} completed "
            f"profile/unit samples across {active_parallelism} active slots"
        )
    else:
        summary["eta_seconds"] = None
        summary["eta_confidence"] = "unknown"
        summary["eta_basis"] = "insufficient completed samples"

    # Observed-throughput calibration: a supply trough (evening pressure
    # derating, machine loss) is invisible to duration-based projections but
    # shows up immediately in wall-clock completion rates. Expose both rates,
    # and never let the projected ETA promise less than the observed rate
    # supports.
    completion_times.sort()
    summary["eta_throughput_seconds"] = None
    if completion_times:
        def _window_rate(window_s: int) -> float | None:
            cutoff = now - timedelta(seconds=window_s)
            recent = sum(1 for value in completion_times if value >= cutoff)
            return recent * 3600.0 / window_s

        rate_1h = _window_rate(3600)
        rate_6h = _window_rate(6 * 3600)
        summary["throughput_units_per_hour_1h"] = round(rate_1h, 2)
        summary["throughput_units_per_hour_6h"] = round(rate_6h, 2)
        observed_rate = rate_6h if rate_6h > 0 else (rate_1h if rate_1h > 0 else None)
        if observed_rate and remaining_units and summary["eta_seconds"] is not None:
            throughput_eta = remaining_units / observed_rate * 3600.0
            summary["eta_throughput_seconds"] = throughput_eta
            if throughput_eta > float(summary["eta_seconds"]):
                summary["eta_seconds"] = throughput_eta
                if summary["eta_upper_seconds"] is not None:
                    summary["eta_upper_seconds"] = max(
                        float(summary["eta_upper_seconds"]), throughput_eta
                    )
                summary["eta_basis"] = (
                    f"{summary.get('eta_basis')}; calibrated to observed "
                    f"throughput {observed_rate:.1f} units/h over the last "
                    f"6h window"
                )
    else:
        summary["throughput_units_per_hour_1h"] = None
        summary["throughput_units_per_hour_6h"] = None
    if fleet_supply is not None:
        summary["fleet_supply"] = fleet_supply
    if summary["eta_seconds"] is not None:
        summary["eta_updated_at"] = now.isoformat()
    summary["eta_at"] = (
        (now + timedelta(seconds=float(summary["eta_seconds"]))).isoformat()
        if summary["eta_seconds"] is not None
        else None
    )
    blocking_reasons = list(summary.get("blocking_reasons") or [])
    failure_reasons = list(summary.get("failure_reasons") or [])
    if reconciliation_units:
        machines = "、".join(summary["reconciliation_machine_ids"])
        blocking_reasons.insert(0, f"等待 {machines} 对账，原 Attempt 执行状态未知" if machines
                                else "等待原 Attempt 对账，执行状态未知")
    if status == "awaiting_approval" and "等待当前 runtime 的 solver approval" not in blocking_reasons:
        blocking_reasons.append("等待当前 runtime 的 solver approval")
    if status == "awaiting_environment" and "等待执行环境就绪" not in blocking_reasons:
        blocking_reasons.append("等待执行环境就绪")
    if status == "blocked" and "任务被调度条件阻塞" not in blocking_reasons:
        blocking_reasons.append("任务被调度条件阻塞")
    for unit in units:
        reason = unit.get("failure_reason") or unit.get("progress_message")
        unit_status = unit.get("status")
        if reason and unit_status == "failed_retriable":
            blocking_reasons.append(str(reason))
        elif reason and unit_status in {"failed_terminal", "queued"}:
            # Lost scientific coverage is evidence requiring attention, but it
            # does not prevent the Job's remaining eligible Units from running.
            # Queued Units may also retain a previous prelaunch failure after
            # they have already become schedulable again.
            failure_reasons.append(str(reason))
    summary["blocking_reasons"] = list(dict.fromkeys(
        sanitize_failure_text(reason, fallback="operational failure", max_length=320)
        for reason in blocking_reasons
        if reason
    ))[:8]
    summary["failure_reasons"] = list(dict.fromkeys(
        sanitize_failure_text(reason, fallback="unit failure", max_length=320)
        for reason in failure_reasons
        if reason
    ))[:8]
    summary["failed_unit_count"] = sum(
        unit.get("status") in {"failed_retriable", "failed_terminal"}
        for unit in units
    )
    summary["last_transition_reason"] = (
        summary["blocking_reasons"][0]
        if summary["blocking_reasons"]
        else summary.get("last_transition_reason") or f"activity phase: {phase}"
    )
    # Keep the solver and execution boundary visible in every Runs response.
    # The latest Attempt is the only source for effective solver and launch
    # evidence; requested policy remains the Job/Unit contract.
    attempts = [
        attempt
        for unit in units
        for attempt in (unit.get("attempts") or [])
    ]
    latest_attempt = max(
        attempts,
        key=lambda attempt: (
            _aware_datetime(attempt.get("assigned_at"))
            or _aware_datetime(attempt.get("started_at"))
            or datetime.min.replace(tzinfo=timezone.utc)
        ),
        default=None,
    )
    allowed = sorted({
        str(value)
        for unit in units
        for value in (unit.get("allowed_solver_variants") or [])
    })
    summary["solver_contract"] = {
        "requested_policy": summary.get("solver_policy"),
        "resource_mode": summary.get("resource_mode"),
        "allowed_variants": allowed,
        "effective_solver": (latest_attempt or {}).get("solver_variant"),
        "approval_id": summary.get("solver_approval_id")
        or (latest_attempt or {}).get("solver_approval_id"),
        "runtime_version": summary.get("runtime_version")
        or (latest_attempt or {}).get("runtime_version"),
        "blocker_reason": next(
            (reason for reason in summary.get("blocking_reasons", [])
             if "cudss" in str(reason).lower() or "solver" in str(reason).lower()),
            None,
        ),
    }
    summary["execution_boundary"] = {
        key: bool((latest_attempt or {}).get(key))
        for key in ("prepared", "remote_run_allocated", "execution_started", "execution_completed")
    }
    summary.setdefault("record_class", "production")
    return summary


def _request_cached_metadata(method):
    """Clone one small metadata read per request, never a cross-request cache."""
    @wraps(method)
    def read(self, *args, **kwargs):
        cache = self._metadata_read_cache()
        if cache is None:
            return method(self, *args, **kwargs)
        key = ("metadata_read", method.__name__, args, tuple(sorted(kwargs.items())))
        if key not in cache:
            cache[key] = method(self, *args, **kwargs)
        return copy.deepcopy(cache[key])
    return read


class MetadataRepository:
    def __init__(self, database_url: str = "sqlite:///./.state/control-plane.db") -> None:
        connect_args: dict[str, Any] = {}
        engine_args: dict[str, Any] = {}
        if database_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
            parsed = make_url(database_url)
            if parsed.database in {None, "", ":memory:"}:
                engine_args["poolclass"] = StaticPool
            else:
                Path(parsed.database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(database_url, connect_args=connect_args, **engine_args)
        if database_url.startswith("sqlite"):
            @event.listens_for(self.engine, "connect")
            def configure_sqlite_connection(dbapi_connection, _connection_record) -> None:
                cursor = dbapi_connection.cursor()
                try:
                    cursor.execute("PRAGMA busy_timeout=5000")
                    cursor.execute("PRAGMA foreign_keys=ON")
                    cursor.execute("PRAGMA synchronous=NORMAL")
                    cursor.execute("PRAGMA wal_autocheckpoint=1000")
                finally:
                    cursor.close()

            if parsed.database not in {None, "", ":memory:"}:
                with self.engine.connect() as connection:
                    mode = connection.exec_driver_sql("PRAGMA journal_mode=WAL").scalar_one()
                    if str(mode).lower() != "wal":
                        raise RuntimeError(f"SQLite WAL mode is unavailable: {mode}")
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)
        self._bound_submission_session = None
        self._submission_operations_lock = threading.RLock()
        self._atomic_context = threading.local()
        self._job_write_context = threading.local()
        self._read_metadata_context = threading.local()
        self._read_connection_context = threading.local()
        # A read scope normally wraps a GET, but nested operational helpers
        # must still observe their own writes and a rolled-back transaction.
        @event.listens_for(self.engine, "after_cursor_execute")
        def invalidate_request_metadata(_connection, _cursor, _statement, _parameters, execution, _many):
            if execution.isinsert or execution.isupdate or execution.isdelete:
                cache = getattr(self._read_metadata_context, "cache", None)
                if cache is not None:
                    cache.clear()
        self._job_locks_guard = threading.Lock()
        self._job_locks: dict[str, threading.RLock] = {}
        # New Job receipt timestamps are allocated under one short-lived
        # repository lock.  SQLite still remains the authority across
        # repository instances; the lock only avoids needless same-process
        # collisions before the database transaction reaches the write.
        self._job_submission_lock = threading.RLock()
        self._job_summary_cache_lock = threading.Lock()
        self._job_summary_cache: dict[tuple[str, int], str] = {}
        self._job_summary_cache_characters = 0
        self._duration_history_load_lock = threading.Lock()
        self._duration_history_cache: tuple[float, dict[str, tuple[float, ...]]] | None = None
        self._reconciliation_snapshot_lock = threading.Lock()
        from .reconciliation_read_projection import ReconciliationReadProjection
        self._reconciliation_read_projection = ReconciliationReadProjection()

    def init_schema(self) -> None:
        # A concurrent control-plane writer can invalidate a SQLite read
        # snapshot before initialization upgrades it to a write transaction.
        # Retry the whole transaction, not the failed statement/snapshot.
        for attempt in range(5):
            try:
                self._init_schema_once()
                return
            except OperationalError as exc:
                code = getattr(exc.orig, "sqlite_errorcode", None)
                if (
                    self.engine.dialect.name != "sqlite"
                    or code is None
                    or (code & 0xFF) not in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
                    or attempt == 4
                ):
                    raise
                time.sleep(0.1 * (2 ** attempt))

    def _init_schema_once(self) -> None:
        self._backup_sqlite_before_migration()
        from . import metadata_actions  # Register additive durable metadata receipts.
        Base.metadata.create_all(self.engine)
        ReadModelBase.metadata.create_all(self.engine)
        # Read-model version 2 stores only fields consumed by cluster insights.
        # Nullable additions let the ordinary revision/version backfill populate
        # existing databases before a reader can use the new facts.
        def migrate_read_columns():
            with self.engine.connect() as connection:
                # API and Dispatcher may open the same old DB together. The
                # inspection and every ALTER must run behind the same writer
                # gate, otherwise both starters can observe a missing column.
                if self.engine.dialect.name == "sqlite":
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                else:
                    connection.begin()
                    if self.engine.dialect.name == "postgresql":
                        connection.exec_driver_sql("LOCK TABLE job_read_models IN ACCESS EXCLUSIVE MODE")
                read_columns_added = False
                for table_name, column_name, sql_type in (
                    ("job_read_models", "insight_payload", "JSON"),
                    ("unit_read_models", "insight_payload", "JSON"),
                    ("attempt_read_models", "allocated_cpus", "FLOAT"),
                    ("attempt_read_models", "started_epoch_us", "BIGINT"),
                    ("attempt_read_models", "finished_epoch_us", "BIGINT"),
                ):
                    columns = {column["name"] for column in inspect(connection).get_columns(table_name)}
                    if column_name not in columns:
                        connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {sql_type}"))
                        read_columns_added = True
                if read_columns_added:
                    connection.execute(update(JobReadRow).values(projection_version=0))
                for table in ReadModelBase.metadata.sorted_tables:
                    for index in table.indexes:
                        index.create(connection, checkfirst=True)
                connection.commit()
        self._retry_sqlite_write(migrate_read_columns)
        # create_all skips indexes added to a table that already exists.
        for index in JobRow.__table__.indexes:
            index.create(self.engine, checkfirst=True)
        # create_all does not add columns to an existing SQLite pilot DB.
        # These additive migrations keep the deployed metadata store usable
        # without introducing a second migration system during incubation.
        if self.engine.dialect.name == "sqlite":
            columns = {column["name"] for column in inspect(self.engine).get_columns("jobs")}
            if "revision" not in columns:
                with self.engine.begin() as connection:
                    connection.execute(text("ALTER TABLE jobs ADD COLUMN revision INTEGER NOT NULL DEFAULT 0"))
            if "operational_payload" not in columns:
                with self.engine.begin() as connection:
                    connection.execute(text("ALTER TABLE jobs ADD COLUMN operational_payload JSON"))
            event_columns = {
                column["name"] for column in inspect(self.engine).get_columns("audit_events")
            }
            if "sequence" not in event_columns:
                with self.engine.begin() as connection:
                    connection.execute(text("ALTER TABLE audit_events ADD COLUMN sequence INTEGER"))
            with self.engine.begin() as connection:
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                from .reconciliation_read_projection import install_reconciliation_projection
                install_reconciliation_projection(connection)

        with self._session() as session, session.begin():
            # Routine Dispatcher starts must not deserialize the entire audit
            # history or issue a no-op UPDATE against a healthy counter.
            next_sequence = (session.scalar(select(func.max(EventRow.sequence))) or 0) + 1
            missing = session.scalars(
                select(EventRow).where(EventRow.sequence.is_(None))
                .order_by(EventRow.created_at, EventRow.event_id)
            ).all()
            for row in missing:
                payload = dict(row.payload or {})
                payload["sequence"] = next_sequence
                row.sequence = next_sequence
                row.payload = payload
                next_sequence += 1
            counter = session.get(EventSequenceRow, "global")
            if counter is None:
                session.add(EventSequenceRow(sequence_id="global", next_sequence=next_sequence))
            elif counter.next_sequence < next_sequence:
                session.execute(
                    update(EventSequenceRow)
                    .where(
                        EventSequenceRow.sequence_id == "global",
                        EventSequenceRow.next_sequence < next_sequence,
                    )
                    .values(next_sequence=next_sequence)
                )

        if self.engine.dialect.name == "sqlite":
            with self.engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE UNIQUE INDEX IF NOT EXISTS "
                        "ix_audit_events_sequence ON audit_events (sequence)"
                    )
                )
        self._backfill_job_operational_payloads()
        self.rebuild_read_models()

    def _backfill_job_operational_payloads(self, *, batch_size: int = 8) -> None:
        """Populate the read model in bounded transactions for legacy rows."""
        while True:
            with self._session() as session, session.begin():
                rows = session.scalars(
                    select(JobRow)
                    .where(JobRow.operational_payload.is_(None))
                    .order_by(JobRow.created_at)
                    .limit(batch_size)
                ).all()
                if not rows:
                    return
                for row in rows:
                    row.operational_payload = _stored_job_operational_projection(
                        row.payload or {}
                    )

    def rebuild_read_models(self, *, force: bool = False, batch_size: int = 32) -> int:
        """Idempotent bounded backfill; force also repairs missing child rows.

        A Job and its revision are read under the writer lock so backfill cannot
        overwrite a projection that a concurrent operational mutation refreshed.
        """
        if batch_size < 1:
            raise ValueError("read-model batch size must be positive")
        if force:
            with self._job_summary_cache_lock:
                self._job_summary_cache.clear()
                self._job_summary_cache_characters = 0
        cursor = ""
        rebuilt = 0
        while True:
            with self._session() as session, session.begin():
                if self.engine.dialect.name == "sqlite":
                    self._begin_immediate(session)
                statement = select(JobRow).outerjoin(
                    JobReadRow, JobReadRow.job_id == JobRow.job_id,
                ).where(JobRow.job_id > cursor)
                if not force:
                    statement = statement.where(or_(
                        JobReadRow.job_id.is_(None),
                        JobReadRow.revision != JobRow.revision,
                        JobReadRow.projection_version != READ_MODEL_VERSION,
                    ))
                rows = session.scalars(statement.order_by(JobRow.job_id).limit(batch_size)
                                       .with_for_update(of=JobRow)).all()
                if not rows:
                    return rebuilt
                for row in rows:
                    projection = row.operational_payload or _stored_job_operational_projection(row.payload or {})
                    projection = dict(projection, revision=row.revision)
                    replace_job_read_model(session, projection)
                    rebuilt += 1
                cursor = rows[-1].job_id

    def _backup_sqlite_before_migration(self) -> None:
        """Create one online backup before the additive 0.8 schema is applied."""
        if self.engine.dialect.name != "sqlite":
            return
        database = make_url(str(self.engine.url)).database
        if not database or database == ":memory:":
            return
        database_path = Path(database).expanduser().resolve()
        if not database_path.is_file():
            return
        existing_tables = set(inspect(self.engine).get_table_names())
        required_tables = {
            "machine_control_tickets",
            "control_operation_runs",
            "machine_command_results",
            "dispatcher_control_tickets",
            "break_glass_config",
            "alerts",
            "origin_import_receipts",
        }
        event_columns = (
            {column["name"] for column in inspect(self.engine).get_columns("audit_events")}
            if "audit_events" in existing_tables
            else set()
        )
        if required_tables.issubset(existing_tables) and "sequence" in event_columns:
            return
        backup_path = database_path.with_suffix(database_path.suffix + ".pre-0.9.0.bak")
        temporary = backup_path.with_suffix(backup_path.suffix + ".tmp")
        temporary.unlink(missing_ok=True)
        source = sqlite3.connect(database_path)
        destination = sqlite3.connect(temporary)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        temporary.replace(backup_path)

    def ensure_dataset_mode(self, mode: str) -> DatasetMetadata:
        with self._session() as session, session.begin():
            row = session.get(DatasetMetadataRow, "global")
            if row is None:
                metadata = DatasetMetadata(mode=mode)
                session.add(DatasetMetadataRow(dataset_id="global", payload=_payload(metadata)))
                return metadata
            metadata = DatasetMetadata.model_validate(row.payload)
            if metadata.mode != mode:
                raise ValueError(
                    f"database is marked as {metadata.mode!r} and cannot start in {mode!r} mode"
                )
            return metadata

    def get_dataset_metadata(self) -> DatasetMetadata | None:
        with self._session() as session:
            row = session.get(DatasetMetadataRow, "global")
            return DatasetMetadata.model_validate(row.payload) if row else None

    def _transaction_session(self) -> Session | None:
        return self._bound_submission_session or getattr(self._atomic_context, "session", None)

    @contextmanager
    def read_connection_scope(self):
        """Reuse one checkout, while each helper keeps its own Session/transaction."""
        if self._transaction_session() is not None or getattr(self._read_connection_context, "active", False):
            yield self
            return
        self._read_connection_context.active = True
        try:
            if isinstance(self.engine.pool, StaticPool):
                yield self
            else:
                with self.engine.connect() as connection:
                    self._read_connection_context.connection = connection
                    try:
                        yield self
                    finally:
                        self._read_connection_context.connection = None
        finally:
            self._read_connection_context.active = False

    @contextmanager
    def read_metadata_cache(self):
        """Memoize small profile/grant/fleet reads for one synchronous request.

        Every request gets a fresh scope; authorization and execution-policy
        changes are observed on the next request, with no persistent TTL cache.
        """
        previous = getattr(self._read_metadata_context, "cache", None)
        if previous is not None:
            yield self
            return
        self._read_metadata_context.cache = {}
        try:
            yield self
        finally:
            self._read_metadata_context.cache = None

    def _metadata_read_cache(self):
        # Atomic read-modify-write helpers must query their bound transaction,
        # rather than a snapshot created before that transaction began.
        if self._transaction_session() is not None:
            return None
        return getattr(self._read_metadata_context, "cache", None)

    def _session(self) -> Session:
        bound = self._transaction_session()
        if bound is not None:
            return _BorrowedSubmissionSession(bound)
        connection = getattr(self._read_connection_context, "connection", None)
        if connection is not None:
            return self.sessions(bind=connection)
        return self.sessions()

    @contextmanager
    def _borrow_transaction(self, session):
        previous = getattr(self._atomic_context, "session", None)
        self._atomic_context.session = session.session if isinstance(session, _BorrowedSubmissionSession) else session
        try:
            yield self
        finally:
            self._atomic_context.session = previous

    @contextmanager
    def _operational_write_hook(self, hook):
        previous = getattr(self._job_write_context, "hook", None)
        self._job_write_context.hook = hook
        try:
            yield
        finally:
            self._job_write_context.hook = previous

    def _run_operational_write_hook(self, session, job, expected_revision):
        hook = getattr(self._job_write_context, "hook", None)
        if hook is None:
            return
        # The gate must read SQL, not a possibly cached ORM identity. An
        # independently committed concurrent envelope wins before ledger writes.
        actual_revision = session.scalar(select(JobRow.revision).where(
            JobRow.job_id == job.job_id).with_for_update())
        if actual_revision != expected_revision:
            job.revision = expected_revision
            raise RevisionConflictError(f"stale job revision for {job.job_id}: expected {expected_revision}")
        with self._borrow_transaction(session), self._operational_write_hook(None):
            hook(job)

    @contextmanager
    def atomic_write(self):
        """Join existing helpers in one atomic write on this calling thread.

        Busy recovery only retries acquiring the transaction before the caller
        runs. A callback requiring whole-body retry uses submission_transaction.
        """
        if self._transaction_session() is not None:
            yield self
            return
        if getattr(self._read_connection_context, "active", False):
            raise RuntimeError("cannot start a write transaction inside a read connection scope")
        session = None
        for attempt in range(8):
            candidate = self.sessions()
            try:
                candidate.begin()
                if self.engine.dialect.name == "sqlite":
                    candidate.execute(text("BEGIN IMMEDIATE"))
                else:
                    candidate.scalar(select(EventSequenceRow).where(
                        EventSequenceRow.sequence_id == "global").with_for_update())
                session = candidate
                break
            except (OperationalError, sqlite3.OperationalError) as exc:
                candidate.close()
                if self.engine.dialect.name != "sqlite" or "locked" not in str(exc).lower() or attempt == 7:
                    raise
                time.sleep(min(0.05 * (2 ** attempt), 1.0))
        try:
            self._atomic_context.session = session
            yield self
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            self._atomic_context.session = None
            session.close()

    @staticmethod
    def _begin_immediate(session) -> None:
        if not isinstance(session, _BorrowedSubmissionSession):
            session.execute(text("BEGIN IMMEDIATE"))

    def submission_transaction(self, operation):
        """Serialize and atomically persist operation, Job, plans and audit.

        The scoped copy makes borrowing thread-local to this callback, leaving
        every ordinary repository caller's existing transaction behavior intact.
        SQLite acquires its writer before reads; other engines lock the durable
        singleton receipt gate. A failure rolls back the entire aggregate.
        """
        if self._transaction_session() is not None:
            return operation(self)
        if getattr(self._read_connection_context, "active", False):
            raise RuntimeError("cannot start a submission transaction inside a read connection scope")
        def write():
            with self.sessions() as session, session.begin():
                if self.engine.dialect.name == "sqlite":
                    self._begin_immediate(session)
                else:
                    session.scalar(select(EventSequenceRow).where(EventSequenceRow.sequence_id == "global").with_for_update())
                scoped = copy.copy(self)
                scoped._bound_submission_session = session
                result = operation(scoped)
                session.flush()
                return result
        with self._submission_operations_lock, self._job_submission_lock:
            return self._retry_sqlite_write(write)


    def get_submission_operation(self, operation_id: str):
        from .submission_operations import SubmissionOperation
        with self._session() as session:
            row = session.get(SubmissionOperationRow, operation_id)
            return SubmissionOperation.model_validate(_hydrate_payload(session, row.payload)) if row is not None else None


    def get_member_retirement(self, machine_id: str) -> dict | None:
        with self._session() as session:
            row = session.get(MemberRetirementRow, machine_id)
            return copy.deepcopy(row.payload) if row is not None else None


    def put_member_retirement(self, receipt: dict) -> None:
        with self._session() as session, session.begin():
            row = session.get(MemberRetirementRow, receipt["machine_id"])
            if row is None:
                row = MemberRetirementRow(machine_id=receipt["machine_id"], operation_id=receipt["operation_id"])
            elif any(row.payload.get(key) != receipt.get(key) for key in (
                "operation_id", "machine_owner_id", "actor_id", "root_uuid", "runtime_version", "request_sha256"
            )):
                raise ValueError("member retirement identity cannot change")
            row.payload = copy.deepcopy(receipt)
            session.add(row)


    def list_member_retirement_jobs(self, machine_id: str) -> list[JobEnvelope]:
        """Include unresolved historic Attempts even if Unit assignment changed."""
        statement = select(JobRow.job_id, JobRow.operational_payload).where(or_(
            select(UnitReadRow.job_id).where(UnitReadRow.job_id == JobRow.job_id,
                UnitReadRow.assigned_machine_id == machine_id).exists(),
            select(AttemptReadRow.job_id).where(AttemptReadRow.job_id == JobRow.job_id,
                AttemptReadRow.machine_id == machine_id,
                AttemptReadRow.state.not_in({"completed", "failed", "cancelled"})).exists(),
        ))
        with self._session() as session:
            jobs = []
            for row in session.execute(statement):
                projection = row.operational_payload
                if projection is None:
                    projection = _stored_job_operational_projection(session.scalar(
                        select(JobRow.payload).where(JobRow.job_id == row.job_id)) or {})
                jobs.append(_operational_projection_to_job(projection))
            return jobs


    def put_submission_operation(self, operation) -> None:
        with self._session() as session, session.begin():
            row = session.get(SubmissionOperationRow, operation.operation_id)
            previous = row.payload if row is not None else None
            if row is None:
                row = SubmissionOperationRow(operation_id=operation.operation_id)
            elif row.actor_id != operation.actor_id or row.payload_sha256 != operation.payload_sha256 or (row.job_id is not None and row.job_id != operation.job_id):
                raise ValueError("durable submission operation binding cannot change")
            row.actor_id = operation.actor_id
            row.project_id = operation.project_id
            row.payload_sha256 = operation.payload_sha256
            row.job_id = operation.job_id
            payload = _compact_declarative_items(session, operation.model_dump(mode="json"))
            _reconcile_blob_reference_counts(session, previous, payload)
            row.payload = payload
            session.add(row)


    def _retry_sqlite_write(
        self,
        operation,
        *,
        attempts: int = 8,
    ):
        """Retry one complete transaction after transient SQLite lock loss."""
        if self._transaction_session() is not None:
            return operation()
        for attempt_index in range(attempts):
            try:
                return operation()
            except (OperationalError, sqlite3.OperationalError) as exc:
                if (
                    self.engine.dialect.name != "sqlite"
                    or "locked" not in str(exc).lower()
                    or attempt_index + 1 >= attempts
                ):
                    raise
                time.sleep(min(0.05 * (2 ** attempt_index), 1.0))
        raise RuntimeError("unreachable SQLite retry state")

    def put_profile(self, profile: ExecutionProfile) -> None:
        with self._session() as session, session.begin():
            row = session.get(ProfileRow, profile.profile_id) or ProfileRow(profile_id=profile.profile_id)
            row.payload = _payload(profile)
            session.add(row)
        cache = self._metadata_read_cache()
        if cache is not None:
            cache.pop(("profile", profile.profile_id), None)

    def put_user(self, user: UserAccount) -> None:
        with self._session() as session, session.begin():
            row = session.get(UserRow, user.user_id) or UserRow(user_id=user.user_id)
            row.active = user.active
            row.payload = _payload(user)
            session.add(row)

    def get_user(self, user_id: str) -> UserAccount | None:
        with self._session() as session:
            row = session.get(UserRow, user_id)
            return UserAccount.model_validate(row.payload) if row else None

    def list_users(self) -> list[UserAccount]:
        with self._session() as session:
            return [UserAccount.model_validate(row.payload) for row in session.scalars(select(UserRow))]

    def put_token(self, token: ApiTokenRecord) -> None:
        with self._session() as session, session.begin():
            row = session.get(TokenRow, token.token_id) or TokenRow(token_id=token.token_id)
            row.user_id = token.user_id
            row.token_hash = token.token_hash
            row.active = token.active
            row.payload = _payload(token)
            session.add(row)

    def get_token_by_hash(self, token_hash: str) -> ApiTokenRecord | None:
        with self._session() as session:
            row = session.scalar(select(TokenRow).where(TokenRow.token_hash == token_hash))
            return ApiTokenRecord.model_validate(row.payload) if row else None

    def get_token(self, token_id: str) -> ApiTokenRecord | None:
        with self._session() as session:
            row = session.get(TokenRow, token_id)
            return ApiTokenRecord.model_validate(row.payload) if row else None

    def list_tokens(self, user_id: str | None = None) -> list[ApiTokenRecord]:
        statement = select(TokenRow).order_by(TokenRow.token_id)
        if user_id is not None:
            statement = statement.where(TokenRow.user_id == user_id)
        with self._session() as session:
            return [ApiTokenRecord.model_validate(row.payload) for row in session.scalars(statement)]

    def put_machine_credential(self, credential: MachineAgentCredential) -> None:
        with self._session() as session, session.begin():
            row = session.get(MachineCredentialRow, credential.credential_id) or MachineCredentialRow(
                credential_id=credential.credential_id,
            )
            row.machine_id = credential.machine_id
            row.token_hash = credential.token_hash
            row.active = credential.active
            row.payload = _payload(credential)
            session.add(row)

    def get_machine_credential_by_hash(self, token_hash: str) -> MachineAgentCredential | None:
        with self._session() as session:
            row = session.scalar(
                select(MachineCredentialRow).where(MachineCredentialRow.token_hash == token_hash)
            )
            return MachineAgentCredential.model_validate(row.payload) if row else None

    def get_machine_credential(self, credential_id: str) -> MachineAgentCredential | None:
        with self._session() as session:
            row = session.get(MachineCredentialRow, credential_id)
            return MachineAgentCredential.model_validate(row.payload) if row else None

    def list_machine_credentials(self, machine_id: str | None = None) -> list[MachineAgentCredential]:
        statement = select(MachineCredentialRow).order_by(MachineCredentialRow.credential_id)
        if machine_id is not None:
            statement = statement.where(MachineCredentialRow.machine_id == machine_id)
        with self._session() as session:
            return [
                MachineAgentCredential.model_validate(row.payload)
                for row in session.scalars(statement)
            ]

    def get_profile(self, profile_id: str) -> ExecutionProfile | None:
        cache = self._metadata_read_cache()
        key = ("profile", profile_id)
        if cache is not None and key in cache:
            cached = cache[key]
            return cached.model_copy(deep=True) if cached is not None else None
        with self._session() as session:
            row = session.get(ProfileRow, profile_id)
            result = ExecutionProfile.model_validate(row.payload) if row else None
        if cache is not None:
            cache[key] = result.model_copy(deep=True) if result is not None else None
        return result

    def list_profiles(self) -> list[ExecutionProfile]:
        with self._session() as session:
            return [ExecutionProfile.model_validate(row.payload) for row in session.scalars(select(ProfileRow))]

    def put_project_grant(self, grant: ProjectGrant) -> None:
        with self._session() as session, session.begin():
            row = session.get(ProjectGrantRow, grant.project_id) or ProjectGrantRow(project_id=grant.project_id)
            row.approved = grant.approved
            row.payload = _payload(grant)
            session.add(row)
        cache = self._metadata_read_cache()
        if cache is not None:
            cache.pop(("grant", grant.project_id), None)
            cache.pop("all_grants", None)

    def get_project_grant(self, project_id: str) -> ProjectGrant | None:
        cache = self._metadata_read_cache()
        key = ("grant", project_id)
        if cache is not None and (key in cache or "all_grants" in cache):
            cached = cache[key] if key in cache else cache["all_grants"].get(project_id)
            return cached.model_copy(deep=True) if cached is not None else None
        with self._session() as session:
            statement = select(ProjectGrantRow).where(ProjectGrantRow.project_id == project_id)
            if self._transaction_session() is not None:
                statement = statement.with_for_update()
            row = session.scalar(statement)
            result = ProjectGrant.model_validate(row.payload) if row else None
        if cache is not None:
            cache[key] = result.model_copy(deep=True) if result is not None else None
        return result

    def list_project_grants(self) -> list[ProjectGrant]:
        cache = self._metadata_read_cache()
        if cache is not None and "all_grants" in cache:
            return [grant.model_copy(deep=True) for grant in cache["all_grants"].values()]
        with self._session() as session:
            result = [ProjectGrant.model_validate(row.payload) for row in session.scalars(select(ProjectGrantRow))]
        if cache is not None:
            cache["all_grants"] = {grant.project_id: grant.model_copy(deep=True) for grant in result}
        return result

    def put_project_registration(self, request: ProjectRegistrationRequest) -> None:
        with self._session() as session, session.begin():
            row = session.get(ProjectRegistrationRow, request.registration_id) or ProjectRegistrationRow(
                registration_id=request.registration_id
            )
            row.project_id = request.project_id
            row.requested_by = request.requested_by
            row.status = request.status.value
            row.created_at = request.created_at
            row.payload = _payload(request)
            session.add(row)

    def get_project_registration(self, registration_id: str) -> ProjectRegistrationRequest | None:
        with self._session() as session:
            statement = select(ProjectRegistrationRow).where(ProjectRegistrationRow.registration_id == registration_id)
            if self._transaction_session() is not None:
                statement = statement.with_for_update()
            row = session.scalar(statement)
            return ProjectRegistrationRequest.model_validate(row.payload) if row else None

    def list_project_registrations(
        self,
        *,
        requested_by: str | None = None,
    ) -> list[ProjectRegistrationRequest]:
        statement = select(ProjectRegistrationRow).order_by(
            ProjectRegistrationRow.created_at.desc(),
            ProjectRegistrationRow.registration_id,
        )
        if requested_by is not None:
            statement = statement.where(ProjectRegistrationRow.requested_by == requested_by)
        with self._session() as session:
            return [
                ProjectRegistrationRequest.model_validate(row.payload)
                for row in session.scalars(statement)
            ]

    def put_origin_adapter(self, adapter: OriginAdapterRegistration) -> None:
        with self._session() as session, session.begin():
            row = session.get(OriginAdapterRow, adapter.adapter_id) or OriginAdapterRow(
                adapter_id=adapter.adapter_id
            )
            row.active = adapter.active
            row.payload = _payload(adapter)
            session.add(row)

    def get_origin_adapter(self, adapter_id: str) -> OriginAdapterRegistration | None:
        with self._session() as session:
            row = session.get(OriginAdapterRow, adapter_id)
            return OriginAdapterRegistration.model_validate(row.payload) if row else None

    def list_origin_adapters(self) -> list[OriginAdapterRegistration]:
        with self._session() as session:
            return [
                OriginAdapterRegistration.model_validate(row.payload)
                for row in session.scalars(select(OriginAdapterRow).order_by(OriginAdapterRow.adapter_id))
            ]

    def put_machine(self, machine: MachineState) -> None:
        def write() -> None:
            with self._session() as session, session.begin():
                row = session.get(MachineRow, machine.machine_id) or MachineRow(machine_id=machine.machine_id)
                row.owner_user_id = machine.owner_user_id
                row.last_heartbeat_at = machine.last_heartbeat_at
                row.payload = _payload(machine)
                session.add(row)

        self._retry_sqlite_write(write)

    @_request_cached_metadata
    def get_machine(self, machine_id: str) -> MachineState | None:
        with self._session() as session:
            row = session.get(MachineRow, machine_id)
            return MachineState.model_validate(row.payload) if row else None

    @_request_cached_metadata
    def list_machines(self) -> list[MachineState]:
        with self._session() as session:
            rows = session.scalars(select(MachineRow).order_by(MachineRow.machine_id)).all()
            return [MachineState.model_validate(row.payload) for row in rows]

    def _lock_machine_health_write(self, session: Session, machine_id: str) -> None:
        # pysqlite's legacy deferred SELECT is not a read-modify-write lock.
        # Acquire before reading the JSON so writers cannot lose other channels.
        if self.engine.dialect.name == "sqlite":
            self._begin_immediate(session)
        else:
            session.execute(select(MachineRow.machine_id).where(
                MachineRow.machine_id == machine_id,
            ).with_for_update())

    def put_machine_operational_status(self, status: MachineOperationalStatus) -> None:
        def write() -> None:
            with self._session() as session, session.begin():
                self._lock_machine_health_write(session, status.machine_id)
                row = session.get(MachineOperationalStatusRow, status.machine_id) or MachineOperationalStatusRow(
                    machine_id=status.machine_id
                )
                merged = merge_channel_evidence(
                    status, MachineOperationalStatus.model_validate(row.payload) if row.payload else None,
                )
                row.payload = _payload(merged)
                session.add(row)

        self._retry_sqlite_write(write)

    def put_machine_observation(
        self,
        machine: MachineState,
        status: MachineOperationalStatus | None,
        sample: MetricSample,
    ) -> bool:
        """Persist one observation aggregate atomically and reject stale samples.

        The machine payload, operational decision, and raw metric evidence are
        one fact.  Keeping them in a single transaction prevents readers from
        observing a new process count with an old capacity decision.
        """

        if sample.machine_id != machine.machine_id:
            raise ValueError("metric sample and machine IDs must match")
        if sample.sample_kind != "raw":
            raise ValueError("machine observation evidence must be a raw metric sample")
        # Check ordering before payload consistency. A delayed SSH sample is
        # expected operational noise and must not be reported as a malformed
        # current observation.
        incoming_at = _aware_datetime(machine.metrics.observed_at)
        with self._session() as session:
            current_row = session.get(MachineRow, machine.machine_id)
            current_at = (
                _aware_datetime((current_row.payload or {}).get("metrics", {}).get("observed_at"))
                if current_row is not None else None
            )
        if current_at is not None and incoming_at is not None and incoming_at < current_at:
            return False
        if sample.recorded_at != machine.metrics.observed_at:
            raise ValueError("metric sample timestamp must match machine observation")
        if (
            sample.metrics.external_process_count
            != machine.metrics.external_process_count
        ):
            raise ValueError("raw metric external process count must match machine observation")
        if (
            sample.metrics.external_process_set_hash
            != machine.metrics.external_process_set_hash
        ):
            raise ValueError("raw metric process-set hash must match machine observation")
        if (
            machine.metrics.external_process_count
            != machine.metrics.external_load.external_process_count
        ):
            raise ValueError("external process count must match load evidence")
        if status is not None and status.machine_id != machine.machine_id:
            raise ValueError("operational status and machine IDs must match")
        if status is not None and status.telemetry_state == TelemetryState.LIVE:
            if status.last_metric_at != machine.metrics.observed_at:
                raise ValueError("operational metric timestamp must match machine observation")
            if status.capacity_decision_at != machine.metrics.observed_at:
                raise ValueError("capacity decision timestamp must match machine observation")
            if (
                status.external_process_count
                != machine.metrics.external_process_count
            ):
                raise ValueError("operational external process count must match machine observation")
            if (
                status.external_process_set_hash
                != machine.metrics.external_process_set_hash
            ):
                raise ValueError("operational process-set hash must match machine observation")
            if not status.observation_consistent:
                raise ValueError("inconsistent operational observation cannot be persisted")

        def write() -> bool:
            with self._session() as session, session.begin():
                self._lock_machine_health_write(session, machine.machine_id)
                machine_row = session.get(MachineRow, machine.machine_id)
                if machine_row is None:
                    raise KeyError(f"machine not found: {machine.machine_id}")
                current_at = _aware_datetime(machine_row.payload.get("metrics", {}).get("observed_at"))
                incoming_at = _aware_datetime(machine.metrics.observed_at)
                if current_at is not None and incoming_at is not None and incoming_at < current_at:
                    return False

                # Supplementary SSH disk evidence has its own observation
                # clock. A concurrent legacy outbound heartbeat prepared
                # before that probe must not erase it with newer CPU metrics.
                current_disk = machine_row.payload.get("metrics", {}).get("execution_disk")
                incoming_disk = machine.metrics.execution_disk
                if current_disk:
                    current_disk_at = _aware_datetime(current_disk.get("observed_at"))
                    if incoming_disk is None or (
                        current_disk_at is not None
                        and _aware_datetime(incoming_disk.observed_at) < current_disk_at
                    ):
                        return False

                status_row = None
                if status is not None:
                    status_row = session.get(MachineOperationalStatusRow, status.machine_id)
                    if status_row is None:
                        status_row = MachineOperationalStatusRow(machine_id=status.machine_id)
                    previous_checked = _aware_datetime((status_row.payload or {}).get("last_checked_at"))
                    incoming_checked = _aware_datetime(status.last_checked_at)
                    if (
                        previous_checked is not None
                        and incoming_checked is not None
                        and incoming_checked < previous_checked
                    ):
                        return False

                machine_row.owner_user_id = machine.owner_user_id
                machine_row.last_heartbeat_at = machine.last_heartbeat_at
                machine_row.payload = _payload(machine)
                session.add(machine_row)

                if status is not None and status_row is not None:
                    merged = merge_channel_evidence(
                        status, MachineOperationalStatus.model_validate(status_row.payload) if status_row.payload else None,
                    )
                    status_row.payload = _payload(merged)
                    session.add(status_row)

                sample_row = session.get(MetricSampleRow, sample.sample_id)
                if sample_row is None:
                    sample_row = MetricSampleRow(sample_id=sample.sample_id)
                sample_row.machine_id = sample.machine_id
                sample_row.sample_kind = sample.sample_kind
                sample_row.recorded_at = sample.recorded_at
                sample_row.payload = _payload(sample)
                session.add(sample_row)
            return True

        return self._retry_sqlite_write(write)

    def put_machine_operational_status_if_newer(
        self,
        status: MachineOperationalStatus,
    ) -> bool:
        """Persist status-only transport evidence without allowing time reversal."""

        def write() -> bool:
            with self._session() as session, session.begin():
                self._lock_machine_health_write(session, status.machine_id)
                row = session.get(MachineOperationalStatusRow, status.machine_id)
                if row is None:
                    row = MachineOperationalStatusRow(machine_id=status.machine_id)
                previous_checked = _aware_datetime((row.payload or {}).get("last_checked_at"))
                incoming_checked = _aware_datetime(status.last_checked_at)
                if (
                    previous_checked is not None
                    and incoming_checked is not None
                    and incoming_checked < previous_checked
                ):
                    return False
                merged = merge_channel_evidence(
                    status, MachineOperationalStatus.model_validate(row.payload) if row.payload else None,
                )
                row.payload = _payload(merged)
                session.add(row)
            return True

        return self._retry_sqlite_write(write)

    def put_machine_channel_observation(
        self,
        machine_id: str,
        source: str,
        observation: ChannelObservation,
    ) -> None:
        """Merge one authenticated channel sample under the metadata transaction.

        Channel freshness is independent of whether an older raw metric payload
        was rejected. A fast outbound stream must not starve SSH liveness checks.
        This entry point is internal; source identity is not supplied by a node.
        """
        if source not in {"ssh", "outbound"}:
            raise ValueError("unsupported observation channel")

        def write() -> None:
            with self._session() as session, session.begin():
                self._lock_machine_health_write(session, machine_id)
                if session.get(MachineRow, machine_id) is None:
                    raise KeyError(f"machine not found: {machine_id}")
                row = session.get(MachineOperationalStatusRow, machine_id)
                previous = MachineOperationalStatus.model_validate(row.payload) if row and row.payload else None
                incoming = (previous or MachineOperationalStatus(machine_id=machine_id)).model_copy(deep=True)
                incoming.connection_evidence = {source: observation}
                merged = merge_channel_evidence(incoming, previous)
                if row is None:
                    row = MachineOperationalStatusRow(machine_id=machine_id)
                row.payload = _payload(merged)
                session.add(row)

        self._retry_sqlite_write(write)

    @_request_cached_metadata
    def get_machine_operational_status(self, machine_id: str) -> MachineOperationalStatus | None:
        with self._session() as session:
            row = session.get(MachineOperationalStatusRow, machine_id)
            if row is None:
                return None
            return age_machine_operational_status(
                MachineOperationalStatus.model_validate(row.payload)
            )

    def put_pressure_override_ticket(self, ticket: PressureOverrideTicket) -> None:
        with self._session() as session, session.begin():
            row = session.get(PressureOverrideTicketRow, ticket.ticket_id) or PressureOverrideTicketRow(
                ticket_id=ticket.ticket_id,
                machine_id=ticket.machine_id,
                expires_at=ticket.expires_at,
                payload={},
            )
            row.machine_id = ticket.machine_id
            row.expires_at = ticket.expires_at
            row.payload = _payload(ticket)
            session.add(row)

    def get_pressure_override_ticket(self, ticket_id: str) -> PressureOverrideTicket | None:
        with self._session() as session:
            row = session.get(PressureOverrideTicketRow, ticket_id)
            return PressureOverrideTicket.model_validate(row.payload) if row else None

    def delete_pressure_override_ticket(self, ticket_id: str) -> None:
        with self._session() as session, session.begin():
            row = session.get(PressureOverrideTicketRow, ticket_id)
            if row is not None:
                session.delete(row)

    def put_admin_operation_ticket(self, ticket: AdminOperationTicket) -> None:
        with self._session() as session, session.begin():
            row = session.get(AdminOperationTicketRow, ticket.ticket_id) or AdminOperationTicketRow(
                ticket_id=ticket.ticket_id,
                job_id=ticket.job_id,
                expires_at=ticket.expires_at,
                payload={},
            )
            row.job_id = ticket.job_id
            row.expires_at = ticket.expires_at
            row.payload = _payload(ticket)
            session.add(row)

    def get_admin_operation_ticket(self, ticket_id: str) -> AdminOperationTicket | None:
        with self._session() as session:
            row = session.get(AdminOperationTicketRow, ticket_id)
            return AdminOperationTicket.model_validate(row.payload) if row else None

    def delete_admin_operation_ticket(self, ticket_id: str) -> None:
        with self._session() as session, session.begin():
            row = session.get(AdminOperationTicketRow, ticket_id)
            if row is not None:
                session.delete(row)

    def put_machine_control_ticket(self, ticket: MachineControlTicket) -> None:
        with self._session() as session, session.begin():
            row = session.get(MachineControlTicketRow, ticket.ticket_id) or MachineControlTicketRow(
                ticket_id=ticket.ticket_id,
                action=ticket.action.value,
                expires_at=ticket.expires_at,
                payload={},
            )
            row.action = ticket.action.value
            row.expires_at = ticket.expires_at
            row.payload = _payload(ticket)
            session.add(row)

    def get_machine_control_ticket(self, ticket_id: str) -> MachineControlTicket | None:
        with self._session() as session:
            row = session.get(MachineControlTicketRow, ticket_id)
            return MachineControlTicket.model_validate(row.payload) if row else None

    def delete_machine_control_ticket(self, ticket_id: str) -> None:
        with self._session() as session, session.begin():
            row = session.get(MachineControlTicketRow, ticket_id)
            if row is not None:
                session.delete(row)

    def list_machine_control_tickets(self) -> list[MachineControlTicket]:
        with self._session() as session:
            rows = session.scalars(
                select(MachineControlTicketRow).order_by(MachineControlTicketRow.expires_at.desc())
            ).all()
            return [MachineControlTicket.model_validate(row.payload) for row in rows]

    def put_control_operation_run(self, run: ControlOperationRun) -> None:
        def write() -> None:
            with self._session() as session, session.begin():
                if self.engine.dialect.name == "sqlite":
                    self._begin_immediate(session)
                row = session.get(ControlOperationRunRow, run.operation_id) or ControlOperationRunRow(
                    operation_id=run.operation_id,
                    ticket_id=run.ticket_id,
                    action=run.action.value,
                    state=run.state.value,
                    updated_at=run.updated_at,
                    payload={},
                )
                row.ticket_id = run.ticket_id
                row.action = run.action.value
                row.state = run.state.value
                row.updated_at = run.updated_at
                row.payload = _payload(run)
                session.add(row)

        self._retry_sqlite_write(write)

    def get_control_operation_run(self, operation_id: str) -> ControlOperationRun | None:
        with self._session() as session:
            row = session.get(ControlOperationRunRow, operation_id)
            return ControlOperationRun.model_validate(row.payload) if row else None

    def list_control_operation_runs(self, limit: int = 100) -> list[ControlOperationRun]:
        with self._session() as session:
            rows = session.scalars(
                select(ControlOperationRunRow).order_by(ControlOperationRunRow.updated_at.desc()).limit(limit)
            ).all()
            return [ControlOperationRun.model_validate(row.payload) for row in rows]

    def put_machine_command_result(self, result: MachineCommandResult) -> None:
        with self._session() as session, session.begin():
            row = session.get(MachineCommandResultRow, result.command_id) or MachineCommandResultRow(
                command_id=result.command_id,
                machine_id=result.machine_id,
                action=result.action.value,
                state=result.state.value,
                payload={},
            )
            row.machine_id = result.machine_id
            row.action = result.action.value
            row.state = result.state.value
            row.payload = _payload(result)
            session.add(row)

    def get_machine_command_result(self, command_id: str) -> MachineCommandResult | None:
        with self._session() as session:
            row = session.get(MachineCommandResultRow, command_id)
            return MachineCommandResult.model_validate(row.payload) if row else None

    def put_dispatcher_control_ticket(self, ticket: DispatcherControlTicket) -> None:
        def write() -> None:
            with self._session() as session, session.begin():
                if self.engine.dialect.name == "sqlite":
                    self._begin_immediate(session)
                row = session.get(DispatcherControlTicketRow, ticket.ticket_id) or DispatcherControlTicketRow(
                    ticket_id=ticket.ticket_id,
                    action=ticket.action.value,
                    expires_at=ticket.expires_at,
                    payload={},
                )
                row.action = ticket.action.value
                row.expires_at = ticket.expires_at
                row.payload = _payload(ticket)
                session.add(row)

        self._retry_sqlite_write(write)

    def get_dispatcher_control_ticket(self, ticket_id: str) -> DispatcherControlTicket | None:
        with self._session() as session:
            row = session.get(DispatcherControlTicketRow, ticket_id)
            return DispatcherControlTicket.model_validate(row.payload) if row else None

    def delete_dispatcher_control_ticket(self, ticket_id: str) -> None:
        def write() -> None:
            with self._session() as session, session.begin():
                if self.engine.dialect.name == "sqlite":
                    self._begin_immediate(session)
                row = session.get(DispatcherControlTicketRow, ticket_id)
                if row is not None:
                    session.delete(row)

        self._retry_sqlite_write(write)

    def put_break_glass_config(self, config: BreakGlassConfig) -> None:
        with self._session() as session, session.begin():
            row = session.get(BreakGlassConfigRow, config.config_id) or BreakGlassConfigRow(
                config_id=config.config_id,
                payload={},
            )
            row.payload = _payload(config)
            session.add(row)

    def get_break_glass_config(self) -> BreakGlassConfig | None:
        with self._session() as session:
            row = session.get(BreakGlassConfigRow, "global")
            return BreakGlassConfig.model_validate(row.payload) if row else None

    def put_alert(self, alert: AlertRecord) -> None:
        with self._session() as session, session.begin():
            row = session.get(AlertRow, alert.alert_id) or AlertRow(
                alert_id=alert.alert_id,
                severity=alert.severity.value,
                status=alert.status.value,
                subject_type=alert.subject_type,
                subject_id=alert.subject_id,
                last_seen_at=alert.last_seen_at,
                payload={},
            )
            row.severity = alert.severity.value
            row.status = alert.status.value
            row.subject_type = alert.subject_type
            row.subject_id = alert.subject_id
            row.last_seen_at = alert.last_seen_at
            row.payload = _payload(alert)
            session.add(row)

    def put_attempt_collection_alert(
        self,
        alert: AlertRecord,
        *,
        job_id: str,
        work_unit_id: str,
        expected_attempt_id: str,
        latch_circuit: bool = False,
    ) -> bool:
        """Keep late abandoned collection errors out of alerts and fleet controls."""
        if alert.subject_type != "attempt" or alert.subject_id != expected_attempt_id:
            raise ValueError("collection alert producer identity does not match")

        def write() -> bool:
            with self._session() as session, session.begin():
                if self.engine.dialect.name == "sqlite":
                    self._begin_immediate(session)
                    job_row = session.get(JobRow, job_id)
                else:
                    job_row = session.scalar(
                        select(JobRow).where(JobRow.job_id == job_id).with_for_update()
                    )
                if job_row is None:
                    return False
                projection = job_row.operational_payload or _stored_job_operational_projection(job_row.payload or {})
                unit = next((item for item in projection.get("work_units", [])
                             if item.get("work_unit_id") == work_unit_id), None)
                attempts = unit.get("attempts", []) if unit is not None else []
                if not attempts:
                    return False
                latest = attempts[-1]
                if (latest.get("attempt_id") != expected_attempt_id
                        or latest.get("state") in {"abandoned", "cancel_pending", "cancelled", "completed"}
                        or latest.get("abandonment") is not None
                        or latest.get("cancel_requested_at") is not None):
                    return False
                row = session.get(AlertRow, alert.alert_id) or AlertRow(alert_id=alert.alert_id)
                row.severity = alert.severity.value
                row.status = alert.status.value
                row.subject_type = alert.subject_type
                row.subject_id = alert.subject_id
                row.last_seen_at = alert.last_seen_at
                row.payload = _payload(alert)
                session.add(row)
                if latch_circuit:
                    session.flush()
                    status_row = session.get(DispatcherStatusRow, "dispatcher") or DispatcherStatusRow(status_id="dispatcher")
                    status = DispatcherStatus.model_validate(status_row.payload) if status_row.payload else DispatcherStatus()
                    if status.blocked_reason in {"", "pending_reconciliation", "quarantined_reconciliation", "collection_circuit_breaker"}:
                        causes = status.collection_circuit_alert_ids if status.blocked_reason == "collection_circuit_breaker" else []
                        unsettled = {item.alert_id for item in self._collection_alert_rows(session) if item.status != "resolved"}
                        status.collection_circuit_alert_ids = sorted(set(causes) | unsettled | {alert.alert_id})
                        status.accepting_assignments = False
                        status.control_mode = "drain"
                        status.blocked_reason = "collection_circuit_breaker"
                        status.auto_resume_allowed = False
                        status.updated_at = datetime.now(timezone.utc)
                        status_row.payload = _payload(status)
                        session.add(status_row)
            return True

        return self._retry_sqlite_write(write)

    def get_alert(self, alert_id: str) -> AlertRecord | None:
        with self._session() as session:
            row = session.get(AlertRow, alert_id)
            return AlertRecord.model_validate(row.payload) if row else None

    def list_alerts(self, *, include_resolved: bool = False, limit: int = 500) -> list[AlertRecord]:
        statement = select(AlertRow).order_by(AlertRow.last_seen_at.desc()).limit(limit)
        if not include_resolved:
            statement = statement.where(AlertRow.status != "resolved")
        with self._session() as session:
            return [AlertRecord.model_validate(row.payload) for row in session.scalars(statement)]

    @_request_cached_metadata
    def list_machine_operational_statuses(self) -> list[MachineOperationalStatus]:
        with self._session() as session:
            return [
                age_machine_operational_status(
                    MachineOperationalStatus.model_validate(row.payload)
                )
                for row in session.scalars(select(MachineOperationalStatusRow))
            ]

    def _fleet_supply_snapshot(self) -> dict[str, Any]:
        """Machine-side supply summary for Job views.

        Agents watching a Job through a restricted bridge cannot see the Fleet
        page; a supply trough (pressure derating, telemetry loss) otherwise
        has to be guessed from the Job's own completion counter.
        """
        statuses = self.list_machine_operational_statuses()
        pressure_states: dict[str, int] = {}
        telemetry_states: dict[str, int] = {}
        capacity_total = 0
        for status in statuses:
            pressure_key = str(status.pressure_state)
            telemetry_key = str(status.telemetry_state)
            pressure_states[pressure_key] = pressure_states.get(pressure_key, 0) + 1
            telemetry_states[telemetry_key] = telemetry_states.get(telemetry_key, 0) + 1
            if status.effective_capacity is not None:
                capacity_total += status.effective_capacity
        return {
            "machines_total": len(statuses),
            "pressure_states": pressure_states,
            "telemetry_states": telemetry_states,
            "effective_capacity_total": capacity_total,
        }

    def put_metric_sample(self, sample: MetricSample) -> None:
        def write() -> None:
            with self._session() as session, session.begin():
                row = session.get(MetricSampleRow, sample.sample_id) or MetricSampleRow(sample_id=sample.sample_id)
                row.machine_id = sample.machine_id
                row.sample_kind = sample.sample_kind
                row.recorded_at = sample.recorded_at
                row.payload = _payload(sample)
                session.add(row)

        self._retry_sqlite_write(write)

    def list_metric_samples(
        self,
        machine_id: str,
        *,
        sample_kind: str,
        since: datetime,
        limit: int = 5000,
    ) -> list[MetricSample]:
        statement = (
            select(MetricSampleRow)
            .where(
                MetricSampleRow.machine_id == machine_id,
                MetricSampleRow.sample_kind == sample_kind,
                MetricSampleRow.recorded_at >= since,
            )
            .order_by(MetricSampleRow.recorded_at)
            .limit(limit)
        )
        with self._session() as session:
            return [MetricSample.model_validate(row.payload) for row in session.scalars(statement)]

    def purge_metric_samples(self, *, raw_before: datetime, minute_before: datetime) -> None:
        with self._session() as session, session.begin():
            session.execute(
                delete(MetricSampleRow).where(
                    MetricSampleRow.sample_kind == "raw",
                    MetricSampleRow.recorded_at < raw_before,
                )
            )
            session.execute(
                delete(MetricSampleRow).where(
                    MetricSampleRow.sample_kind == "minute",
                    MetricSampleRow.recorded_at < minute_before,
                )
            )

    def _shared_cpu_usage(self, session, machine_id: str, *, exclude_job_id=None) -> int:
        from .shared_capacity import cpu_claims
        statement = select(JobRow.job_id, JobRow.operational_payload)
        if exclude_job_id is not None:
            statement = statement.where(JobRow.job_id != exclude_job_id)
        total = 0
        for identity, projection in session.execute(statement):
            if projection is None:
                legacy = session.scalar(select(JobRow.payload).where(JobRow.job_id == identity))
                projection = _stored_job_operational_projection(legacy or {})
            total += cpu_claims(_operational_projection_to_job(projection)).get(machine_id, 0)
        return total

    def _check_shared_cpu_commit(self, session, job, existing) -> None:
        """Serialize allocation against the same Policy row used by owner edits.

        SQLite acquires its writer before any snapshot. Other databases lock
        host policies in stable order. No schema, scientific JSON, or wire change.
        """
        from .shared_capacity import cpu_claims, SharedCapacityConflict
        previous = None
        if existing is not None:
            projection = existing.operational_payload
            if projection is None:
                projection = _stored_job_operational_projection(existing.payload or {})
            previous = _operational_projection_to_job(projection)
        before, after = cpu_claims(previous), cpu_claims(job)
        from .shared_capacity import ACTIVE_ATTEMPT_STATES, ACTIVE_UNIT_STATES

        def attempt_claims(value):
            claims = {}
            for unit in value.work_units if value is not None else ():
                attempts = [attempt for attempt in unit.attempts
                            if attempt.state in ACTIVE_ATTEMPT_STATES]
                if attempts:
                    for attempt in attempts:
                        machine_id = attempt.machine_id or unit.assigned_machine_id
                        if machine_id:
                            resolved = attempt.resolved_resources or unit.resolved_resources
                            resources = resolved.resources if resolved else unit.resources
                            claims[(machine_id, 'attempt', unit.work_unit_id, attempt.attempt_id)] = resources.cpus
                elif (unit.assigned_machine_id
                      and unit.status.value in ACTIVE_UNIT_STATES):
                    resources = unit.resolved_resources.resources if unit.resolved_resources else unit.resources
                    claims[(unit.assigned_machine_id, 'unit', unit.work_unit_id)] = resources.cpus
            return claims

        old_claims, current_claims = attempt_claims(previous), attempt_claims(job)
        for machine_id in sorted(after):
            new_claims = [cpus for identity, cpus in current_claims.items()
                          if identity[0] == machine_id and cpus > old_claims.get(identity, 0)]
            if after[machine_id] <= before.get(machine_id, 0) and not new_claims:
                continue  # Results, reconciliation and releases must remain possible.
            row = session.scalar(select(PolicyRow).where(PolicyRow.machine_id == machine_id).with_for_update())
            if row is None:
                continue
            policy = MachinePolicy.model_validate(row.payload)
            if not policy.shared_machine and policy.full_cpu_override is None:
                continue
            if policy.full_cpu_override is None and after[machine_id] <= before.get(machine_id, 0):
                continue
            machine_row = session.get(MachineRow, machine_id)
            if machine_row is None:
                raise SharedCapacityConflict('shared machine identity no longer exists')
            machine = MachineState.model_validate(machine_row.payload)
            if policy.effective_mode().value != 'open':
                raise SharedCapacityConflict('shared machine stopped accepting new work')
            if policy.full_cpu_override is not None:
                # Keep owner-mode locking and the per-process hardware/policy cap;
                # only the cumulative CPU budget is intentionally oversubscribed.
                cap = policy.effective_cpu_cap(machine.total_cpus)
                if policy.full_cpu_override.max_threads_per_attempt is not None:
                    cap = min(cap, policy.full_cpu_override.max_threads_per_attempt)
                # Apply the latest locked policy to new/increased identities,
                # including replacement claims with no aggregate CPU growth.
                # Existing active Attempts keep their truthful frozen resources.
                if any(cpus > cap for cpus in new_claims):
                    raise SharedCapacityConflict('full CPU per-process cap would be exceeded at commit')
                continue
            used = self._shared_cpu_usage(session, machine_id, exclude_job_id=job.job_id)
            if used + after[machine_id] > policy.effective_cpu_cap(machine.total_cpus):
                raise SharedCapacityConflict('shared machine CPU reserve would be exceeded at commit')

    def _check_shared_policy_commit(self, session, policy, previous) -> None:
        from .shared_capacity import SharedCapacityConflict
        if previous is not None:
            for name in ('shared_machine', 'cpu_reserve_percent'):
                if name not in policy.model_fields_set:
                    setattr(policy, name, getattr(previous, name))
            if previous.shared_machine and not policy.shared_machine:
                raise SharedCapacityConflict('shared machine reserve cannot be removed through ordinary policy edits')
        if not policy.shared_machine:
            return
        machine_row = session.get(MachineRow, policy.machine_id)
        if machine_row is None:
            return
        machine = MachineState.model_validate(machine_row.payload)
        if (previous is not None and previous.shared_machine
                and policy.effective_cpu_cap(machine.total_cpus) >= previous.effective_cpu_cap(machine.total_cpus)):
            return
        if machine.metrics.running_units or self._shared_cpu_usage(session, policy.machine_id):
            raise SharedCapacityConflict('drain active work before enabling or tightening a shared machine CPU reserve')

    def put_policy(self, policy: MachinePolicy, *, full_cpu_override_authorized: bool = False,
                   admin_override_authorized: bool = False,
                   expected_policy_sha256: str | None = None,
                   expected_policy_payload_sha256: str | None = None) -> None:
        if expected_policy_payload_sha256 is not None:
            _validate_policy_payload_sha256(expected_policy_payload_sha256)
        def write():
            with self._session() as session, session.begin():
                if self.engine.dialect.name == 'sqlite':
                    self._begin_immediate(session)
                row = session.scalar(select(PolicyRow).where(
                    PolicyRow.machine_id == policy.machine_id).with_for_update())
                if expected_policy_payload_sha256 is not None:
                    from .hashing import sha256_value
                    if row is None or sha256_value(row.payload) != expected_policy_payload_sha256:
                        raise PolicyRevisionConflict('machine policy changed; read the same machine again')
                previous = MachinePolicy.model_validate(row.payload) if row is not None else None
                if previous is not None and not admin_override_authorized:
                    if policy.admin_mode_override != previous.admin_mode_override:
                        raise ValueError('admin override requires administrator authorization')
                    for name in ('admin_override_reason', 'admin_override_actor', 'admin_override_at'):
                        setattr(policy, name, getattr(previous, name))
                if session.get(MemberRetirementRow, policy.machine_id) is not None and policy.owner_mode.value == "open":
                    raise ValueError("member retirement remains active; owner cannot reopen execution")
                if expected_policy_sha256 is not None:
                    from .hashing import sha256_value
                    if previous is None or sha256_value(previous.model_dump(mode='json')) != expected_policy_sha256:
                        raise ValueError('machine policy changed; read the same machine again')
                existing_override = previous.full_cpu_override if previous else None
                if 'full_cpu_override' not in policy.model_fields_set:
                    policy.full_cpu_override = existing_override
                elif policy.full_cpu_override != existing_override and not full_cpu_override_authorized:
                    raise ValueError('full CPU override requires its dedicated authorization workflow')
                if (policy.full_cpu_override is not None
                        and (policy.member_execution_limit is not None
                             or (previous is not None and previous.member_execution_limit is not None))):
                    raise ValueError('full CPU override is unavailable for invitation-limited machines')
                self._check_shared_policy_commit(session, policy, previous)
                existing_limit = previous.member_execution_limit if previous else None
                if existing_limit is not None:
                    if policy.member_execution_limit is not None and policy.member_execution_limit != existing_limit:
                        raise ValueError('conditional admission changed; refresh policy before updating')
                    # A stale owner/telemetry update cannot erase a concurrently
                    # recorded or revoked admission. Dedicated consent/revocation
                    # transactions change that field directly under their own locks.
                    policy.member_execution_limit = existing_limit
                if row is None:
                    row = PolicyRow(machine_id=policy.machine_id)
                row.payload = _payload(policy)
                session.add(row)
        self._retry_sqlite_write(write)

    @_request_cached_metadata
    def get_policy(self, machine_id: str) -> MachinePolicy | None:
        with self._session() as session:
            statement = select(PolicyRow).where(PolicyRow.machine_id == machine_id)
            if self._transaction_session() is not None:
                statement = statement.with_for_update()
            row = session.scalar(statement)
            return MachinePolicy.model_validate(row.payload) if row else None

    def get_policy_revision(self, machine_id: str) -> dict[str, Any] | None:
        """Hash the raw stored JSON and validate its DTO from the same SELECT."""
        from .hashing import sha256_value
        with self._session() as session:
            statement = select(PolicyRow.payload).where(PolicyRow.machine_id == machine_id)
            if self._transaction_session() is not None:
                statement = statement.with_for_update()
            payload = session.scalar(statement)
            if payload is None:
                return None
            return {'machine_id': machine_id, 'revision_hash': sha256_value(payload),
                'policy': MachinePolicy.model_validate(payload).model_dump(mode='json')}

    def preload_machine_policies(self, machine_ids: Iterable[str]) -> None:
        """Prime only this read request's normal get_policy cache in one query.

        Writers keep their existing individually locked reads. Cached models
        remain private: get_policy still deep-copies every returned value.
        """
        cache = self._metadata_read_cache()
        if cache is None:
            return
        keys = {machine_id: ("metadata_read", "get_policy", (machine_id,), ())
                for machine_id in set(machine_ids)}
        missing = [machine_id for machine_id, key in keys.items() if key not in cache]
        if not missing:
            return
        with self._session() as session:
            policies = {row.machine_id: MachinePolicy.model_validate(row.payload)
                        for row in session.scalars(select(PolicyRow).where(PolicyRow.machine_id.in_(missing)))}
        for machine_id in missing:
            cache[keys[machine_id]] = policies.get(machine_id)

    def put_approval(self, approval: ApprovalRecord) -> None:
        with self._session() as session, session.begin():
            row = session.get(ApprovalRow, approval.approval_id) or ApprovalRow(approval_id=approval.approval_id)
            row.machine_id = approval.machine_id
            row.active = approval.active
            row.payload = _payload(approval)
            session.add(row)

    @_request_cached_metadata
    def list_approvals(self, machine_id: str | None = None) -> list[ApprovalRecord]:
        statement = select(ApprovalRow)
        if machine_id is not None:
            statement = statement.where(ApprovalRow.machine_id == machine_id)
        with self._session() as session:
            return [ApprovalRecord.model_validate(row.payload) for row in session.scalars(statement)]

    def put_solver_approval(self, approval: SolverCompatibilityApproval) -> None:
        with self._session() as session, session.begin():
            row = session.get(SolverApprovalRow, approval.approval_id) or SolverApprovalRow(
                approval_id=approval.approval_id
            )
            row.project_id = approval.project_id
            row.fingerprint = approval.fingerprint
            row.active = approval.active
            row.payload = _payload(approval)
            session.add(row)

    @_request_cached_metadata
    def get_solver_approval(self, approval_id: str) -> SolverCompatibilityApproval | None:
        with self._session() as session:
            row = session.get(SolverApprovalRow, approval_id)
            return SolverCompatibilityApproval.model_validate(row.payload) if row else None

    @_request_cached_metadata
    def list_solver_approvals(
        self,
        *,
        project_id: str | None = None,
        active_only: bool = False,
    ) -> list[SolverCompatibilityApproval]:
        statement = select(SolverApprovalRow)
        if project_id is not None:
            statement = statement.where(SolverApprovalRow.project_id == project_id)
        if active_only:
            statement = statement.where(SolverApprovalRow.active.is_(True))
        with self._session() as session:
            return [
                SolverCompatibilityApproval.model_validate(row.payload)
                for row in session.scalars(statement)
            ]

    def put_partition_plan(self, plan: PartitionPlan) -> None:
        def write() -> None:
            with self._session() as session, session.begin():
                # Acquire the writer before any read or blob autoflush. A
                # deferred read transaction cannot reliably upgrade under WAL
                # contention; retry this complete aggregate, never the plan.
                if self.engine.dialect.name == "sqlite":
                    self._begin_immediate(session)
                row = session.get(PartitionPlanRow, plan.plan_id)
                previous_payload = row.payload if row is not None else None
                if row is None:
                    row = PartitionPlanRow(plan_id=plan.plan_id)
                row.request_hash = plan.request.request_hash
                row.project_id = plan.request.project_id
                row.status = plan.status
                row.created_at = plan.created_at
                compacted_payload = _compact_declarative_items(session, _payload(plan))
                _reconcile_blob_reference_counts(session, previous_payload, compacted_payload)
                row.payload = compacted_payload
                session.add(row)

        self._retry_sqlite_write(write)

    def get_partition_plan(self, plan_id: str) -> PartitionPlan | None:
        with self._session() as session:
            row = session.get(PartitionPlanRow, plan_id)
            return PartitionPlan.model_validate(_hydrate_payload(session, row.payload)) if row else None

    def list_partition_plans(
        self,
        *,
        project_id: str | None = None,
    ) -> list[PartitionPlan]:
        statement = select(PartitionPlanRow).order_by(PartitionPlanRow.created_at.desc())
        if project_id is not None:
            statement = statement.where(PartitionPlanRow.project_id == project_id)
        with self._session() as session:
            return [PartitionPlan.model_validate(_hydrate_payload(session, row.payload)) for row in session.scalars(statement)]

    @staticmethod
    def _as_utc_datetime(value: datetime | str | None) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _next_job_receipt_time(self, session: Session) -> datetime:
        """Allocate a server-owned, strictly increasing Job receipt time.

        ``JobEnvelope.created_at`` is accepted on the wire for compatibility,
        but a newly persisted Job must not inherit a submitter clock.  The
        indexed database maximum is the durable ordering witness; retrying the
        complete transaction after a SQLite write collision makes the same
        rule hold across independently constructed repository instances.
        """
        candidate = datetime.now(timezone.utc)
        latest = self._as_utc_datetime(session.scalar(select(func.max(JobRow.created_at))))
        if latest is not None and latest >= candidate:
            candidate = latest + timedelta(microseconds=1)
        return candidate

    @staticmethod
    def _serialize_job_receipt_write(session: Session) -> None:
        """Acquire the existing database write gate before reading Job order.

        SQLite WAL permits concurrent readers to upgrade stale snapshots when
        they only insert into ``jobs``.  A no-op update of the singleton event
        counter acquires the same writer lock first, so every new Job observes
        the previous committed receipt time, including across processes.
        """
        result = session.execute(
            update(EventSequenceRow)
            .where(EventSequenceRow.sequence_id == "global")
            .values(next_sequence=EventSequenceRow.next_sequence)
        )
        # Some DB drivers report ``-1`` for an unknown row count even when
        # the UPDATE succeeded; only zero unambiguously means the gate row is
        # absent.
        if result.rowcount == 0:
            raise RuntimeError("database receipt-order gate is not initialized")

    def put_job(self, job: JobEnvelope) -> None:
        # Capture caller-owned values because a transient SQLite lock can
        # occur after the model has been incremented for the attempted write.
        # Each retry must start from the same revision and input timestamps.
        original_revision = job.revision
        original_created_at = job.created_at
        original_updated_at = job.updated_at

        def operation() -> None:
            job.revision = original_revision
            job.created_at = original_created_at
            job.updated_at = original_updated_at
            self._put_job_once(job)

        if original_revision == 0 and self._transaction_session() is None:
            with self._job_submission_lock:
                self._retry_sqlite_write(operation)
        else:
            self._retry_sqlite_write(operation)

    def _put_job_once(self, job: JobEnvelope) -> None:
        now = datetime.now(timezone.utc)
        with self._session() as session, session.begin():
            if self.engine.dialect.name == "sqlite":
                self._begin_immediate(session)
            if job.revision == 0:
                self._serialize_job_receipt_write(session)
            row = session.get(JobRow, job.job_id)
            self._check_shared_cpu_commit(session, job, row)
            if row is None:
                if job.revision != 0:
                    raise RevisionConflictError(
                        f"new job {job.job_id} must start at revision 0, got {job.revision}"
                    )
                # The service, rather than a submitter clock, owns receipt
                # order.  This prevents equal microsecond timestamps from
                # falling through to the random Job ID tie-breaker.
                job.created_at = self._next_job_receipt_time(session)
                job.revision = 1
                job.updated_at = max(now, job.created_at)
                compacted_payload = _compact_declarative_items(session, _payload(job))
                operational_payload = _job_operational_projection(job)
                _reconcile_blob_reference_counts(session, None, compacted_payload)
                session.add(JobRow(
                    job_id=job.job_id,
                    request_hash=job.request_hash,
                    user_id=job.user_id,
                    project_id=job.project_id,
                    status=job.status.value,
                    priority=job.priority,
                    created_at=job.created_at,
                    updated_at=job.updated_at,
                    revision=job.revision,
                    payload=compacted_payload,
                    operational_payload=operational_payload,
                ))
                replace_job_read_model(session, operational_payload)
                return
            expected_revision = job.revision
            next_revision = expected_revision + 1
            job.revision = next_revision
            job.updated_at = now
            compacted_payload = _compact_declarative_items(session, _payload(job))
            operational_payload = _job_operational_projection(
                job,
                previous=row.operational_payload,
            )
            _reconcile_blob_reference_counts(session, row.payload, compacted_payload)
            result = session.execute(
                update(JobRow)
                .where(JobRow.job_id == job.job_id, JobRow.revision == expected_revision)
                .values(
                    request_hash=job.request_hash,
                    user_id=job.user_id,
                    project_id=job.project_id,
                    status=job.status.value,
                    priority=job.priority,
                    created_at=job.created_at,
                    updated_at=job.updated_at,
                    revision=next_revision,
                    payload=compacted_payload,
                    operational_payload=operational_payload,
                )
            )
            if result.rowcount != 1:
                job.revision = expected_revision
                raise RevisionConflictError(
                    f"stale job revision for {job.job_id}: expected {expected_revision}"
                )
            replace_job_read_model(session, operational_payload)

    def get_origin_transfer_job(self, job_id: str, unit_id: str | None = None):
        """Fresh authorization/header plus only one unit's scientific payload.

        This internal view must never enter scheduling or persistence APIs.
        It avoids expanding thousands of unrelated scientific blobs per PUT.
        """
        from .origin_transfer import OriginTransferJobView
        with self._session() as session:
            if self.engine.dialect.name == "sqlite":
                # Project in SQLite's JSON engine before Python decoding. The
                # field names are fixed model fields, never client SQL/paths.
                fields = [k for k in OriginTransferJobView.model_fields if k != "work_units"]
                paths = ", ".join(f"'$.{key}'" for key in fields)
                header = session.execute(text(
                    f"SELECT json_extract(payload, {paths}), json_extract(operational_payload, {paths}) "
                    "FROM jobs WHERE job_id=:job_id"), {"job_id": job_id}).first()
                if header is None:
                    return None
                scientific_values = json.loads(header[0])
                operational_values = json.loads(header[1]) if header[1] else [None] * len(fields)
                selected = {key: current if current is not None else original
                            for key, original, current in zip(fields, scientific_values, operational_values)}
                units = []
                if unit_id is not None:
                    def select_unit(column):
                        value = session.execute(text(
                            f"SELECT u.value FROM jobs j, json_each(j.{column}, '$.work_units') u "
                            "WHERE j.job_id=:job_id AND json_extract(u.value, '$.work_unit_id')=:unit_id LIMIT 1"
                        ), {"job_id": job_id, "unit_id": unit_id}).scalar_one_or_none()
                        return json.loads(value) if value is not None else None
                    unit = select_unit("payload")
                    if unit is not None:
                        current = select_unit("operational_payload") or {}
                        unit.update({key: value for key, value in current.items() if key != "atomic_item_count"})
                        units.append(_hydrate_payload(session, unit))
                selected["work_units"] = units
                return OriginTransferJobView.model_validate(selected)
            row = session.get(JobRow, job_id)
            if row is None:
                return None
            scientific, operational = row.payload, row.operational_payload or {}
            selected = {key: _hydrate_payload(session, operational.get(key, scientific.get(key)))
                        for key in OriginTransferJobView.model_fields if key != "work_units"}
            units = []
            if unit_id is not None:
                scientific_unit = next((u for u in scientific.get("work_units", [])
                                        if u.get("work_unit_id") == unit_id), None)
                if scientific_unit is not None:
                    unit = dict(scientific_unit)
                    current = next((u for u in operational.get("work_units", [])
                                    if u.get("work_unit_id") == unit_id), {})
                    unit.update({key: value for key, value in current.items() if key != "atomic_item_count"})
                    units.append(_hydrate_payload(session, unit))
            selected["work_units"] = units
            return OriginTransferJobView.model_validate(selected)

    def get_job(self, job_id: str, *, hydrate_blobs: bool = True) -> JobEnvelope | None:
        with self._session() as session:
            row = session.get(JobRow, job_id)
            return (
                JobEnvelope.model_validate(
                    _hydrate_payload(
                        session,
                        _overlay_job_operational_payload(
                            row.payload,
                            row.operational_payload,
                        ),
                        expand_blobs=hydrate_blobs,
                    )
                )
                if row
                else None
            )

    def get_operational_job(self, job_id: str) -> JobEnvelope | None:
        """Read one scheduler snapshot without touching scientific payloads."""
        with self._session() as session:
            row = session.get(JobRow, job_id)
            if row is None:
                return None
            projection = row.operational_payload or _stored_job_operational_projection(
                row.payload or {}
            )
            return _operational_projection_to_job(projection)

    def _put_job_operational(self, job: JobEnvelope) -> None:
        """CAS-update only mutable state, leaving scientific JSON and blobs intact."""
        now = datetime.now(timezone.utc)
        expected_revision = job.revision
        next_revision = expected_revision + 1
        job.revision = next_revision
        job.updated_at = now
        with self._session() as session, session.begin():
            if self.engine.dialect.name == "sqlite":
                self._begin_immediate(session)
            existing = session.get(JobRow, job.job_id)
            if existing is None:
                job.revision = expected_revision
                raise KeyError(f"job not found: {job.job_id}")
            self._run_operational_write_hook(session, job, expected_revision)
            self._check_shared_cpu_commit(session, job, existing)
            operational_payload = _job_operational_projection(
                job,
                previous=existing.operational_payload,
            )
            result = session.execute(
                update(JobRow)
                .where(
                    JobRow.job_id == job.job_id,
                    JobRow.revision == expected_revision,
                )
                .values(
                    request_hash=job.request_hash,
                    user_id=job.user_id,
                    project_id=job.project_id,
                    status=job.status.value,
                    priority=job.priority,
                    created_at=job.created_at,
                    updated_at=job.updated_at,
                    revision=next_revision,
                    operational_payload=operational_payload,
                )
            )
            if result.rowcount != 1:
                job.revision = expected_revision
                raise RevisionConflictError(
                    f"stale job revision for {job.job_id}: expected {expected_revision}"
                )
            replace_job_read_model(session, operational_payload)

    def get_job_operational_detail(
        self,
        job_id: str,
        *,
        job: JobEnvelope | None = None,
    ) -> dict[str, Any] | None:
        """Return the full Job payload with the same derived state used by Runs."""
        job = job or self.get_job(job_id)
        if job is None:
            return None
        if job.job_id != job_id:
            raise ValueError("operational detail Job identity does not match job_id")
        payload = job.model_dump(mode="json")
        projected_item_count = 0
        projected_item_counts_complete = True
        for unit in payload.get("work_units", []):
            identifiers = unit.get("atomic_item_ids") or []
            item_count = len(identifiers)
            if not item_count:
                total_items = unit.get("total_items")
                if isinstance(total_items, int) and total_items >= 0:
                    item_count = total_items
                else:
                    projected_item_counts_complete = False
            unit["atomic_item_count"] = item_count
            projected_item_count += item_count
        if payload.get("atomic_item_count") is None and projected_item_counts_complete:
            payload["atomic_item_count"] = projected_item_count
        reservations = {
            reservation.work_unit_id: reservation
            for reservation in self.list_dispatch_reservations(active_only=True)
            if reservation.job_id == job_id
            and reservation.state in {"preparing", "prepared", "activating"}
        }
        for unit in payload.get("work_units", []):
            reservation = reservations.get(unit.get("work_unit_id"))
            if reservation is None:
                continue
            unit["activity_state"] = "prepared"
            unit["dispatch_reservation_id"] = reservation.reservation_id
            unit["prepared_at"] = (
                reservation.prepared_at.isoformat()
                if reservation.prepared_at is not None
                else None
            )
        history = self._completed_duration_history().get(job.execution_profile_id, [])
        return _decorate_job_summary(
            payload,
            history,
            fleet_supply=self._fleet_supply_snapshot(),
        )

    def list_job_events(self, job: JobEnvelope, limit: int = 500) -> list[AuditEvent]:
        """Collect events belonging to a Job without exposing unrelated projects."""
        unit_ids = {unit.work_unit_id for unit in job.work_units}
        attempt_ids = {
            attempt.attempt_id
            for unit in job.work_units
            for attempt in unit.attempts
        }
        subject_ids = {job.job_id, *unit_ids, *attempt_ids}
        # Details carry job_id for standardized attempt/unit events. Subject
        # identity covers older records and avoids depending on event wording.
        statement = (
            select(EventRow)
            .where(
                or_(
                    EventRow.subject_id.in_(subject_ids),
                    EventRow.payload["details"]["job_id"].as_string() == job.job_id,
                )
            )
            .order_by(EventRow.sequence.desc())
            .limit(limit)
        )
        with self._session() as session:
            events = [
                AuditEvent.model_validate(row.payload)
                for row in session.scalars(statement)
            ]
        # Work-unit and attempt IDs are deterministic within a partition plan
        # and can be reused by a superseding Job.  Prefer the explicit job ID
        # carried by newer events; for legacy events without that detail, do
        # not leak records created before this Job existed.
        job_created_at = job.created_at
        if job_created_at.tzinfo is None:
            job_created_at = job_created_at.replace(tzinfo=timezone.utc)
        filtered: list[AuditEvent] = []
        for event in events:
            related_job_id = event.details.get("job_id")
            if related_job_id is not None and related_job_id != job.job_id:
                continue
            if (
                related_job_id is None
                and event.subject_id in unit_ids | attempt_ids
            ):
                event_created_at = event.created_at
                if event_created_at.tzinfo is None:
                    event_created_at = event_created_at.replace(tzinfo=timezone.utc)
                if event_created_at < job_created_at:
                    continue
            filtered.append(event)
        return filtered

    def get_job_by_hash(self, request_hash: str) -> JobEnvelope | None:
        with self._session() as session:
            row = session.scalar(select(JobRow).where(JobRow.request_hash == request_hash))
            return (
                JobEnvelope.model_validate(
                    _hydrate_payload(
                        session,
                        _overlay_job_operational_payload(
                            row.payload,
                            row.operational_payload,
                        ),
                    )
                )
                if row
                else None
            )

    @staticmethod
    def _filter_jobs(statement, statuses=None, *, user_id=None, project_id=None,
                     machine_id=None, visibility: JobVisibility | None = None, job_table=JobRow):
        """One predicate for list, counts and aggregates; pagination comes later."""
        if statuses:
            statement = statement.where(job_table.status.in_([str(status) for status in statuses]))
        if user_id is not None:
            statement = statement.where(job_table.user_id == user_id)
        if project_id is not None:
            statement = statement.where(job_table.project_id == project_id)
        if machine_id is not None:
            statement = statement.where(select(UnitReadRow.job_id).where(
                UnitReadRow.job_id == job_table.job_id,
                UnitReadRow.assigned_machine_id == machine_id,
            ).exists())
        if visibility is not None:
            allowed = []
            if visibility.user_id is not None:
                allowed.append(job_table.user_id == visibility.user_id)
            if visibility.project_ids:
                allowed.append(job_table.project_id.in_(sorted(visibility.project_ids)))
            if visibility.machine_ids:
                allowed.append(select(UnitReadRow.job_id).where(
                    UnitReadRow.job_id == job_table.job_id,
                    UnitReadRow.assigned_machine_id.in_(sorted(visibility.machine_ids)),
                ).exists())
            statement = statement.where(or_(*allowed) if allowed else false())
        return statement

    @staticmethod
    def _page_jobs(statement, *, limit, offset):
        statement = statement.order_by(JobRow.created_at.desc(), JobRow.job_id.desc()).offset(offset)
        return statement.limit(limit) if limit is not None else statement

    def list_jobs(
        self, statuses: Iterable[JobStatus] | None = None, *, user_id: str | None = None,
        project_id: str | None = None, machine_id: str | None = None,
        limit: int | None = None, offset: int = 0, hydrate_blobs: bool = True,
        visibility: JobVisibility | None = None,
    ) -> list[JobEnvelope]:
        statement = self._filter_jobs(select(JobRow), statuses, user_id=user_id,
            project_id=project_id, machine_id=machine_id, visibility=visibility)
        statement = self._page_jobs(statement, limit=limit, offset=offset)
        with self._session() as session:
            return [JobEnvelope.model_validate(_hydrate_payload(session,
                _overlay_job_operational_payload(row.payload, row.operational_payload),
                expand_blobs=hydrate_blobs)) for row in session.scalars(statement)]

    def list_operational_jobs(
        self, statuses: Iterable[JobStatus] | None = None, *, user_id: str | None = None,
        project_id: str | None = None, machine_id: str | None = None,
        limit: int | None = None, offset: int = 0, visibility: JobVisibility | None = None,
    ) -> list[JobEnvelope]:
        """Page scheduler snapshots in SQL, without hydrating scientific blobs."""
        statement = self._filter_jobs(select(JobRow.job_id, JobRow.operational_payload), statuses,
            user_id=user_id, project_id=project_id, machine_id=machine_id, visibility=visibility)
        statement = self._page_jobs(statement, limit=limit, offset=offset)
        with self._session() as session:
            jobs = []
            for row in session.execute(statement):
                projection = row.operational_payload
                if projection is None:
                    projection = _stored_job_operational_projection(session.scalar(
                        select(JobRow.payload).where(JobRow.job_id == row.job_id)) or {})
                jobs.append(_operational_projection_to_job(projection))
            return jobs

    def list_job_index(
        self, statuses: Iterable[JobStatus] | None = None, *, user_id: str | None = None,
        project_id: str | None = None, machine_id: str | None = None,
        limit: int | None = None, offset: int = 0, visibility: JobVisibility | None = None,
    ) -> list[dict[str, Any]]:
        """Only indexed scalar columns; authorization is applied before LIMIT."""
        statement = self._filter_jobs(select(JobRow.job_id, JobRow.user_id, JobRow.project_id,
            JobRow.status, JobRow.priority, JobRow.created_at, JobRow.updated_at, JobRow.revision),
            statuses, user_id=user_id, project_id=project_id, machine_id=machine_id, visibility=visibility)
        statement = self._page_jobs(statement, limit=limit, offset=offset)
        with self._session() as session:
            return [dict(row._mapping) for row in session.execute(statement)]

    def count_jobs(self, statuses: Iterable[JobStatus] | None = None, *,
                   user_id: str | None = None, project_id: str | None = None,
                   machine_id: str | None = None, visibility: JobVisibility | None = None) -> int:
        statement = self._filter_jobs(select(func.count()).select_from(JobRow), statuses,
            user_id=user_id, project_id=project_id, machine_id=machine_id, visibility=visibility)
        with self._session() as session:
            return int(session.scalar(statement) or 0)

    def get_job_index(self, job_id: str, *, visibility: JobVisibility | None = None) -> dict[str, Any] | None:
        statement = self._filter_jobs(select(JobRow.job_id, JobRow.user_id, JobRow.project_id,
            JobRow.status, JobRow.priority, JobRow.created_at, JobRow.updated_at, JobRow.revision)
            .where(JobRow.job_id == job_id), visibility=visibility)
        with self._session() as session:
            row = session.execute(statement).one_or_none()
            return dict(row._mapping) if row is not None else None

    @staticmethod
    def pending_job_predicate(states: Iterable[str], *, include_uncertain_failure: bool = True):
        """Indexed candidate Jobs for insights; retain terminal-Job live work."""
        predicates = [select(AttemptReadRow.job_id).where(
            AttemptReadRow.state.in_(sorted({str(state) for state in states})),
        )]
        if include_uncertain_failure:
            predicates.append(select(UnitReadRow.job_id).where(
                UnitReadRow.remote_recovery_pending.is_(True),
            ))
        return or_(*(JobRow.job_id.in_(statement) for statement in predicates))

    def get_job_activity_counts(self, *, user_id: str | None = None,
            project_id: str | None = None, machine_id: str | None = None,
            visibility: JobVisibility | None = None) -> dict[str, int]:
        statement = self._filter_jobs(select(JobReadRow.activity_state, func.count())
            .select_from(JobReadRow), user_id=user_id,
            project_id=project_id, machine_id=machine_id, visibility=visibility, job_table=JobReadRow)
        with self._session() as session:
            counts = dict(session.execute(statement.group_by(JobReadRow.activity_state)).all())
        return {"current": int(counts.get("active", 0) + counts.get("queued", 0)),
                "needs_attention": int(counts.get("recoverable", 0) + counts.get("needs_attention", 0)),
                "history": int(counts.get("history", 0))}

    def get_operations_metrics(self, *, user_id: str | None = None,
            project_id: str | None = None, machine_id: str | None = None,
            visibility: JobVisibility | None = None, now: datetime | None = None) -> dict[str, Any]:
        """Exact operational totals over all matching Jobs and Attempt history."""
        current = _aware_datetime(now) or datetime.now(timezone.utc)
        statement = self._filter_jobs(select(func.count().label("total"),
            func.sum(case((JobReadRow.effective_status == "completed", 1), else_=0)).label("completed"),
            func.sum(case((JobReadRow.effective_status == "queued", 1), else_=0)).label("queued"),
            func.min(case((JobReadRow.effective_status == "queued", JobReadRow.created_at), else_=None)).label("oldest"),
            func.sum(JobReadRow.total_attempts).label("attempts"),
            func.sum(JobReadRow.completed_attempts).label("completed_attempts"),
            func.sum(JobReadRow.migrated_attempts).label("migrated"),
            func.sum(JobReadRow.infrastructure_failures).label("infrastructure"),
            func.sum(JobReadRow.pending_reconciliation).label("reconciliation"))
            .select_from(JobReadRow),
            user_id=user_id, project_id=project_id, machine_id=machine_id, visibility=visibility, job_table=JobReadRow)
        with self._session() as session:
            counts = session.execute(statement).one()
        total_attempts = int(counts.attempts or 0)
        oldest = _aware_datetime(counts.oldest)
        return {"generated_at": current,
            "queue_age_s": max(0.0, (current - oldest).total_seconds()) if oldest else 0.0,
            "total_jobs": int(counts.total), "completed_jobs": int(counts.completed or 0),
            "queued_jobs": int(counts.queued or 0), "attempts": total_attempts,
            "completed_attempts": int(counts.completed_attempts or 0),
            "retry_rate": int(counts.migrated or 0) / total_attempts if total_attempts else 0.0,
            "infrastructure_failure_rate": int(counts.infrastructure or 0) / total_attempts if total_attempts else 0.0,
            "pending_reconciliation": int(counts.reconciliation or 0)}

    def list_active_attempt_ids(self, machine_id: str) -> list[str]:
        statement = select(AttemptReadRow.attempt_id).join(JobRow, JobRow.job_id == AttemptReadRow.job_id).where(
            AttemptReadRow.machine_id == machine_id, AttemptReadRow.state.not_in(TERMINAL_ATTEMPT_STATES))
        with self._session() as session:
            return list(session.scalars(statement.distinct().order_by(AttemptReadRow.attempt_id)))

    def list_active_attempt_counts(self, *, visibility: JobVisibility | None = None) -> dict[str, int]:
        """Count live Attempts even when their Job has a terminal recorded state."""
        return self._attempt_counts_by_machine(visibility=visibility)

    def list_attempt_counts_by_state(self, states: set[str], *,
            visibility: JobVisibility | None = None) -> dict[str, int]:
        normalized = sorted({str(state) for state in states if state})
        return self._attempt_counts_by_machine(states=normalized, visibility=visibility) if normalized else {}

    def _attempt_counts_by_machine(self, *, states=None, visibility=None) -> dict[str, int]:
        statement = select(AttemptReadRow.machine_id,
            func.count(func.distinct(AttemptReadRow.attempt_id))).join(JobRow, JobRow.job_id == AttemptReadRow.job_id)
        statement = statement.where(AttemptReadRow.machine_id.is_not(None))
        statement = statement.where(AttemptReadRow.state.in_(states) if states is not None
                                    else AttemptReadRow.state.not_in(TERMINAL_ATTEMPT_STATES))
        statement = self._filter_jobs(statement, visibility=visibility)
        with self._session() as session:
            return {str(machine): int(count) for machine, count in
                    session.execute(statement.group_by(AttemptReadRow.machine_id))}

    def machine_attempt_state_counts(self, *, visibility: JobVisibility | None = None) -> dict[str, dict[str, int]]:
        """Count each live Attempt identity once within each machine/state group.

        Identities can occur in more than one Job, including with different
        states. Independent DISTINCT expressions preserve the legacy four
        queries' semantics without summing overlapping state counts.
        """
        groups = {
            "active": AttemptReadRow.state.not_in(TERMINAL_ATTEMPT_STATES),
            "running": AttemptReadRow.state == "running",
            "assigned": AttemptReadRow.state.in_({"assigned", "submitting"}),
            "collecting": AttemptReadRow.state.in_({"collecting", "reconcile_pending", "uncertain"}),
        }
        statement = select(AttemptReadRow.machine_id, *(
            func.count(func.distinct(case((predicate, AttemptReadRow.attempt_id)))).label(name)
            for name, predicate in groups.items()
        )).join(JobRow, JobRow.job_id == AttemptReadRow.job_id).where(
            AttemptReadRow.machine_id.is_not(None),
            AttemptReadRow.state.not_in(TERMINAL_ATTEMPT_STATES),
        )
        statement = self._filter_jobs(statement, visibility=visibility)
        result = {name: {} for name in groups}
        with self._session() as session:
            for row in session.execute(statement.group_by(AttemptReadRow.machine_id)):
                for name in groups:
                    count = int(getattr(row, name))
                    if count:
                        result[name][str(row.machine_id)] = count
        return result

    def project_concurrency_facts(self, project_ids: Iterable[str]) -> dict[str, dict[str, int | None]]:
        """Read requested projects' concurrency without hydrating Job histories."""
        selected = sorted(set(project_ids))
        if not selected:
            return {}
        result = {project: {"active_units": 0, "prepared_units": 0, "max_running_units": None}
                  for project in selected}
        active = select(JobRow.project_id, func.count()).join(
            UnitReadRow, UnitReadRow.job_id == JobRow.job_id,
        ).where(JobRow.project_id.in_(selected), JobRow.status.in_({"queued", "running"}),
            UnitReadRow.status.in_({"assigned", "running", "reconcile_pending"}),
        ).group_by(JobRow.project_id)
        prepared = select(JobRow.project_id, func.count()).join(
            DispatchReservationRow, DispatchReservationRow.job_id == JobRow.job_id,
        ).where(JobRow.project_id.in_(selected), JobRow.status.in_({"queued", "running"}),
            DispatchReservationRow.active_key.is_not(None),
            DispatchReservationRow.state.in_({"preparing", "prepared", "activating"}),
        ).group_by(JobRow.project_id)
        with self._session() as session:
            for project, count in session.execute(active):
                result[str(project)]["active_units"] = int(count)
            for project, count in session.execute(prepared):
                result[str(project)]["prepared_units"] = int(count)
            for project, maximum in session.execute(select(
                ProjectGrantRow.project_id, ProjectGrantRow.payload["max_running_units"].as_integer(),
            ).where(ProjectGrantRow.project_id.in_(selected))):
                # Legacy grants omitted this field and use ProjectGrant's
                # default, rather than an unlimited project allocation.
                result[str(project)]["max_running_units"] = int(maximum) if maximum is not None else 4
        return result

    def get_job_execution_summary(self, job_id: str) -> dict[str, Any] | None:
        """One Job's mesh/solver metadata, with no current derived conditions."""
        with self._session() as session, session.begin():
            if self.engine.dialect.name == "sqlite" and not isinstance(session, _BorrowedSubmissionSession):
                session.execute(text("BEGIN"))
            payload = session.scalar(select(JobReadRow.summary_payload).where(JobReadRow.job_id == job_id))
            if payload is None:
                return None
            summary = dict(payload, work_units=[])
            for unit in session.scalars(select(UnitReadRow).where(UnitReadRow.job_id == job_id)
                                        .order_by(UnitReadRow.ordinal)):
                summary["work_units"].append(dict(unit.payload,
                    attempts=[unit.latest_attempt] if unit.latest_attempt else []))
            return summary

    def _summary_current_execution_facts(self, job_ids: list[str]) -> dict[str, bool]:
        """Page-local SQL facts; an older live Attempt still needs current reads."""
        current_unit = select(UnitReadRow.job_id).where(
            UnitReadRow.job_id == JobReadRow.job_id,
            or_(UnitReadRow.status.not_in({"completed", "cancelled", "failed_terminal"}),
                UnitReadRow.remote_recovery_pending.is_(True),
                # Keep local infrastructure recovery on the current path.
                # An older external boundary may make this conservative, but
                # can never incorrectly suppress an execution condition read.
                (UnitReadRow.status == "failed_terminal")
                & (UnitReadRow.latest_attempt["failure_class"].as_string() == "infrastructure")
                & (UnitReadRow.payload["max_attempts"].as_integer() < 10)),
        ).correlate(JobReadRow).exists()
        live_attempt = select(AttemptReadRow.job_id).where(
            AttemptReadRow.job_id == JobReadRow.job_id,
            AttemptReadRow.state.not_in(TERMINAL_ATTEMPT_STATES),
        ).correlate(JobReadRow).exists()
        statement = select(JobReadRow.job_id, or_(
            JobReadRow.activity_state != "history", current_unit, live_attempt,
        )).join(JobRow, JobRow.job_id == JobReadRow.job_id).where(
            JobReadRow.job_id.in_(job_ids), JobReadRow.revision == JobRow.revision,
            JobReadRow.projection_version == READ_MODEL_VERSION,
        )
        with self._session() as session:
            return {str(job): bool(required) for job, required in session.execute(statement)}

    def list_job_summaries(
        self,
        statuses: Iterable[JobStatus] | None = None,
        *,
        user_id: str | None = None,
        project_id: str | None = None,
        machine_id: str | None = None,
        limit: int | None = None,
        offset: int = 0,
        compact: bool = False,
        visibility: JobVisibility | None = None,
    ) -> list[dict[str, Any]]:
        """Read the operational Job contract without scientific payload bytes."""
        # Page authorization and selection precede every optional derived read.
        index = self.list_job_index(
            statuses, user_id=user_id, project_id=project_id, machine_id=machine_id,
            limit=limit, offset=offset, visibility=visibility,
        )
        if not index:
            return []
        eta_history: dict[str, tuple[float, ...]] = {}
        fleet_supply = None
        reservations: dict[tuple[str, str], DispatchReservation] = {}
        current_facts = self._summary_current_execution_facts([str(item["job_id"]) for item in index])

        def decorate(summary: dict[str, Any]) -> dict[str, Any]:
            for unit in summary.get("work_units", []):
                reservation = reservations.get((str(summary["job_id"]), str(unit.get("work_unit_id"))))
                if reservation is None:
                    continue
                unit["activity_state"] = "prepared"
                unit["dispatch_reservation_id"] = reservation.reservation_id
                unit["prepared_at"] = (
                    reservation.prepared_at.isoformat()
                    if reservation.prepared_at is not None
                    else None
                )
            decorated = _decorate_job_summary(
                summary,
                eta_history.get(summary.get("execution_profile_id"), []),
                fleet_supply=fleet_supply if current_facts.get(str(summary["job_id"]), True) else None,
            )
            units = decorated.get("work_units") or []
            decorated["current_execution_required"] = current_facts.get(str(summary["job_id"]), True)
            decorated["unit_count"] = len(units)
            decorated["completed_unit_count"] = sum(
                unit.get("status") == "completed" for unit in units
            )
            decorated["resource_summary"] = copy.deepcopy(
                (units[0].get("resources") if units else None) or {}
            )
            effective_resources: list[tuple[dict[str, Any], str, bool, str]] = []
            solver_counts: dict[str, int] = {}
            for unit in units:
                attempt = (unit.get("attempts") or [])[-1:]
                solver = (
                    attempt[0].get("solver_variant")
                    if attempt
                    else None
                ) or "/".join(unit.get("allowed_solver_variants") or []) or "mumps"
                if attempt and isinstance(attempt[0].get("resolved_resources"), dict):
                    resolved = attempt[0]["resolved_resources"]
                    resources = resolved.get("resources")
                    if isinstance(resources, dict):
                        effective_resources.append((
                            resources,
                            str(resolved.get("source") or "unknown"),
                            str(attempt[0].get("state") or "") in {
                                "assigned",
                                "submitting",
                                "running",
                                "cancel_pending",
                                "reconcile_pending",
                                "uncertain",
                                "collecting",
                            },
                            str(solver),
                        ))
                solver_counts[str(solver)] = solver_counts.get(str(solver), 0) + 1
            decorated["solver_counts"] = solver_counts
            if effective_resources:
                active_resources = [item for item in effective_resources if item[2]]
                selected_resources = active_resources or effective_resources
                sources = sorted({source for _, source, _, _ in selected_resources})
                solvers = sorted({solver for _, _, _, solver in selected_resources})
                decorated["effective_resource_summary"] = {
                    f"{field}_{bound}": operation(
                        int(resources.get(field) or 0)
                        for resources, _, _, _ in selected_resources
                    )
                    for field in ("cpus", "memory_mb", "disk_mb", "gpus")
                    for bound, operation in (("min", min), ("max", max))
                }
                decorated["effective_resource_summary"].update({
                    "sources": sources,
                    "source": sources[0] if len(sources) == 1 else "mixed",
                    "solvers": solvers,
                    "attempt_count": len(effective_resources),
                    "active_attempt_count": len(active_resources),
                    "scope": "active" if active_resources else "latest",
                })
            return decorated

        def compact_attempt(attempt: dict[str, Any]) -> dict[str, Any]:
            fields = {
                "attempt_id",
                "machine_id",
                "external_run_id",
                "state",
                "assigned_at",
                "started_at",
                "finished_at",
                "last_observed_at",
                "cancel_requested_at",
                "collected_at",
                "failure_class",
                "solver_variant",
                "solver_approval_id",
                "solver_compatibility_fingerprint",
                "runtime_version",
                "migrated",
                "prepared",
                "remote_run_allocated",
                "execution_started",
                "execution_completed",
                "execution_end_observed_at",
                "resolved_resources",
            }
            return {key: value for key, value in attempt.items() if key in fields}

        job_ids = [str(item["job_id"]) for item in index]
        revisions = {str(item["job_id"]): int(item["revision"]) for item in index}
        cacheable = self._transaction_session() is None
        with self._job_summary_cache_lock:
            cached = {job_id: self._job_summary_cache.get((job_id, revisions[job_id]))
                      for job_id in job_ids} if cacheable else {}
        # Serialized cache values are immutable; decoding gives every request
        # its own DTO without recursively copying thousands of Python objects.
        projections = {job_id: json.loads(value) for job_id, value in cached.items() if value is not None}
        missing = [job_id for job_id in job_ids if job_id not in projections]
        if missing:
            with self._session() as session, session.begin():
                if self.engine.dialect.name == "sqlite" and not isinstance(session, _BorrowedSubmissionSession):
                    # sqlite3's legacy mode otherwise gives each SELECT a new
                    # snapshot, permitting a mixed revision to enter the cache.
                    session.execute(text("BEGIN"))
                rows = session.execute(select(JobReadRow.job_id, JobReadRow.summary_payload)
                    .where(JobReadRow.job_id.in_(missing)).with_for_update(read=True)).all()
                fresh = {str(row.job_id): dict(row.summary_payload, work_units=[]) for row in rows}
                units = session.scalars(select(UnitReadRow).where(UnitReadRow.job_id.in_(missing))
                                        .order_by(UnitReadRow.job_id, UnitReadRow.ordinal))
                for unit in units:
                    if unit.job_id in fresh:
                        payload = dict(unit.payload)
                        payload["attempts"] = [unit.latest_attempt] if unit.latest_attempt else []
                        fresh[unit.job_id]["work_units"].append(payload)
            for job_id, projection in fresh.items():
                if not cacheable:
                    continue
                encoded = json.dumps(projection, separators=(",", ":"), ensure_ascii=False)
                # Only cache a revision actually observed in both reads. A
                # writer between index and payload reads cannot poison its key.
                if int(projection.get("revision") or 0) != revisions[job_id] or len(encoded) > 1_000_000:
                    continue
                with self._job_summary_cache_lock:
                    for key in list(self._job_summary_cache):
                        if key[0] == job_id:
                            self._job_summary_cache_characters -= len(self._job_summary_cache.pop(key))
                    self._job_summary_cache[(job_id, revisions[job_id])] = encoded
                    self._job_summary_cache_characters += len(encoded)
                    while len(self._job_summary_cache) > 256 or self._job_summary_cache_characters > 4_000_000:
                        oldest = next(iter(self._job_summary_cache))
                        self._job_summary_cache_characters -= len(self._job_summary_cache.pop(oldest))
            projections.update(fresh)

        current = [projection for job_id, projection in projections.items()
                   if current_facts.get(job_id, True)]
        if current:
            fleet_supply = self._fleet_supply_snapshot()
        if any(unit.get("status") in {"assigned", "running", "collecting"}
               for projection in current for unit in projection.get("work_units") or []):
            eta_history = self._completed_duration_history()
        preparable_ids = [str(projection["job_id"]) for projection in current
            if any(unit.get("status") in {"queued", "prepared", "staged", "assigned"}
                   for unit in projection.get("work_units") or [])]
        if preparable_ids:
            with self._session() as session:
                rows = session.scalars(select(DispatchReservationRow).where(
                    DispatchReservationRow.job_id.in_(preparable_ids),
                    DispatchReservationRow.active_key.is_not(None),
                    DispatchReservationRow.state.in_({"preparing", "prepared", "activating"}),
                ))
                for row in rows:
                    reservation = DispatchReservation.model_validate(row.payload)
                    reservations[(reservation.job_id, reservation.work_unit_id)] = reservation

        summaries: list[dict[str, Any]] = []
        for job_id in job_ids:
            projection = projections.get(job_id)
            if projection is None:
                continue
            summary = (
                {
                    key: value
                    for key, value in projection.items()
                    if key in _RUNS_JOB_FIELDS
                }
                if compact
                else dict(projection)
            )
            summary.pop("projection_version", None)
            compact_units: list[dict[str, Any]] = []
            for source_unit in projection.get("work_units") or []:
                compact_unit = (
                    {
                        key: value
                        for key, value in source_unit.items()
                        if key in _RUNS_UNIT_FIELDS
                    }
                    if compact
                    else dict(source_unit)
                )
                compact_unit["required_capabilities"] = sorted(
                    compact_unit.get("required_capabilities") or []
                )
                compact_unit["allowed_solver_variants"] = sorted(
                    compact_unit.get("allowed_solver_variants") or []
                )
                attempts = source_unit.get("attempts") or []
                compact_unit["attempts"] = (
                    [compact_attempt(attempts[-1])] if attempts else []
                )
                if compact_unit.get("failure_reason"):
                    compact_unit["failure_reason"] = sanitize_failure_text(
                        compact_unit["failure_reason"],
                        fallback="work unit failure",
                        max_length=320,
                    )
                if compact_unit.get("progress_message"):
                    compact_unit["progress_message"] = sanitize_failure_text(
                        compact_unit["progress_message"],
                        fallback="work unit progress unavailable",
                        max_length=320,
                    )
                compact_units.append(compact_unit)
            summary["work_units"] = compact_units
            summaries.append(decorate(summary))
        return summaries

    def _completed_duration_history(self) -> dict[str, tuple[float, ...]]:
        """Load compact completed-Unit timing evidence grouped by Profile."""
        now = time.monotonic()
        with self._job_summary_cache_lock:
            cached = self._duration_history_cache
            if cached is not None and now - cached[0] < 10.0:
                # Immutable samples need no recursive copy under the shared
                # lock; callers receive their own small Profile mapping.
                return dict(cached[1])

        with self._session() as session:
            # Scoped GETs already own a checkout. Every other loader must take
            # its connection before the shared lock to preserve that ordering.
            session.connection()
            with self._duration_history_load_lock:
                # Only one caller refreshes the expired timing sample snapshot.
                with self._job_summary_cache_lock:
                    cached = self._duration_history_cache
                    if cached is not None and time.monotonic() - cached[0] < 10.0:
                        return dict(cached[1])
                history: dict[str, list[float]] = {}
                rows = session.execute(select(JobReadRow.execution_profile_id, UnitReadRow.actual_duration_s)
                    .join(UnitReadRow, UnitReadRow.job_id == JobReadRow.job_id)
                    .join(JobRow, JobRow.job_id == JobReadRow.job_id)
                    .where(UnitReadRow.status == "completed", UnitReadRow.actual_duration_s > 0)
                    .order_by(JobRow.updated_at.desc(), JobRow.job_id.desc(), UnitReadRow.ordinal)
                    .limit(10000))
                for profile_id, measured in rows:
                    if profile_id and measured is not None:
                        history.setdefault(str(profile_id), []).append(float(measured))
                with self._job_summary_cache_lock:
                    immutable = {profile: tuple(samples) for profile, samples in history.items()}
                    self._duration_history_cache = (now, immutable)
                return dict(immutable)

    def mutate_job(
        self,
        job_id: str,
        mutation,
        *,
        retries: int = 8,
        hydrate_blobs: bool = True,
        atomic_callback: bool = False,
        before_write: Callable[[JobEnvelope], None] | None = None,
    ) -> JobEnvelope:
        """Apply one aggregate mutation with bounded CAS/SQLite recovery.

        ``hydrate_blobs=False`` selects the operational read/write model. It
        never reads or rewrites the immutable scientific payload column.
        ``before_write`` reserves a ledger after the SQL revision gate, inside
        the actual operational transaction. The ordinary updater keeps its CAS
        read timing; ``atomic_callback`` separately opts an updater into a full
        transaction when its own nested writes require that stronger scope.
        """
        if retries < 1:
            raise ValueError("job mutation retries must be positive")
        if before_write is not None and hydrate_blobs:
            raise ValueError("operational write hooks require hydrate_blobs=False")
        with self._job_locks_guard:
            job_lock = self._job_locks.setdefault(job_id, threading.RLock())
        last_error: Exception | None = None
        # An outer DB transaction already owns the authoritative writer/row
        # gate. Waiting for a local lock here would invert the normal
        # local-lock -> DB order against another Dispatcher thread.
        with job_lock if self._transaction_session() is None else nullcontext():
            for attempt_index in range(retries):
                callback_completed = False
                try:
                    # Updaters may reserve or settle operational ledgers. Bind
                    # their helpers to the Job transaction so a failed CAS or
                    # callback cannot leave an independent committed reservation.
                    with self.atomic_write() if atomic_callback else nullcontext():
                        job = (self.get_job(job_id) if hydrate_blobs
                               else self.get_operational_job(job_id))
                        if job is None:
                            raise KeyError(f"job not found: {job_id}")
                        mutation(job)
                        callback_completed = True
                        if hydrate_blobs:
                            self.put_job(job)
                        else:
                            with self._operational_write_hook(before_write):
                                self._put_job_operational(job)
                        return job
                except (RevisionConflictError, OperationalError) as exc:
                    # Preserve the callback's explicit refusal; only a failed
                    # aggregate write is eligible for the existing CAS retry.
                    if not callback_completed:
                        raise
                    if self._transaction_session() is not None:
                        raise
                    if isinstance(exc, OperationalError) and "locked" not in str(exc).lower():
                        raise
                    last_error = exc
                    if attempt_index + 1 < retries:
                        time.sleep(min(0.05 * (2 ** attempt_index), 1.0))
        if last_error is not None:
            raise last_error
        raise RevisionConflictError(f"failed to update job {job_id}")

    def mutate_job_with_context(self, job_id: str, mutation, *, retries: int = 8,
                                hydrate_blobs: bool = False) -> JobEnvelope:
        """Mutation whose callback and nested ledgers share the Job transaction."""
        return self.mutate_job(job_id, mutation, retries=retries,
                               hydrate_blobs=hydrate_blobs, atomic_callback=True)

    def mutate_job_with_artifact_manifest(
        self,
        job_id: str,
        manifest: ArtifactManifest,
        mutation,
        *,
        retries: int = 8,
    ) -> JobEnvelope:
        """Publish an admissible result and its Job transition in one transaction.

        The callback checks the producer Attempt against the latest persisted
        Job while its row is locked. Returning ``False`` declines publication;
        raising rolls everything back. Scientific payloads are never rewritten.
        """
        if manifest.job_id != job_id:
            raise ValueError("artifact manifest Job identity does not match")
        if retries < 1:
            raise ValueError("job mutation retries must be positive")
        with self._job_locks_guard:
            job_lock = self._job_locks.setdefault(job_id, threading.RLock())
        with job_lock if self._transaction_session() is None else nullcontext():
            for attempt_index in range(retries):
                try:
                    with self._session() as session, session.begin():
                        if self.engine.dialect.name == "sqlite":
                            self._begin_immediate(session)
                            existing = session.get(JobRow, job_id)
                        else:
                            existing = session.scalar(
                                select(JobRow)
                                .where(JobRow.job_id == job_id)
                                .with_for_update()
                            )
                        if existing is None:
                            raise KeyError(f"job not found: {job_id}")
                        projection = existing.operational_payload or _stored_job_operational_projection(
                            existing.payload or {}
                        )
                        current = _operational_projection_to_job(projection)
                        if not any(unit.work_unit_id == manifest.work_unit_id for unit in current.work_units):
                            raise ValueError("artifact manifest WorkUnit identity does not match")
                        with self._borrow_transaction(session):
                            accepted = mutation(current)
                        if accepted is False:
                            return current
                        expected_revision = existing.revision
                        current.revision = expected_revision + 1
                        current.updated_at = datetime.now(timezone.utc)
                        self._check_shared_cpu_commit(session, current, existing)
                        operational_payload = _job_operational_projection(
                            current, previous=existing.operational_payload,
                        )
                        result = session.execute(
                            update(JobRow)
                            .where(JobRow.job_id == job_id, JobRow.revision == expected_revision)
                            .values(
                                request_hash=current.request_hash,
                                user_id=current.user_id,
                                project_id=current.project_id,
                                status=current.status.value,
                                priority=current.priority,
                                created_at=current.created_at,
                                updated_at=current.updated_at,
                                revision=current.revision,
                                operational_payload=operational_payload,
                            )
                        )
                        if result.rowcount != 1:
                            raise RevisionConflictError(f"stale result publication for {job_id}")
                        replace_job_read_model(session, operational_payload)
                        artifact = session.get(ArtifactRow, manifest.work_unit_id) or ArtifactRow(
                            work_unit_id=manifest.work_unit_id,
                            job_id=job_id,
                            created_at=manifest.created_at,
                        )
                        if artifact.job_id != job_id:
                            raise ValueError("artifact WorkUnit belongs to a different Job")
                        artifact.created_at = manifest.created_at
                        artifact.payload = _payload(manifest)
                        session.add(artifact)
                    return current
                except (RevisionConflictError, OperationalError) as exc:
                    if self._transaction_session() is not None:
                        raise
                    if isinstance(exc, OperationalError) and "locked" not in str(exc).lower():
                        raise
                    if attempt_index + 1 == retries:
                        raise
                    time.sleep(min(0.05 * (2 ** attempt_index), 1.0))
        raise RevisionConflictError(f"failed to publish result for {job_id}")

    def acquire_dispatcher_lease(
        self,
        owner_id: str,
        *,
        ttl_s: int = 30,
        now: datetime | None = None,
    ) -> DispatcherLease | None:
        def write() -> DispatcherLease | None:
            with self._session() as session:
                try:
                    with session.begin():
                        # Waiting for a writer/row lock must not consume the
                        # new lease's TTL. Borrowed transactions already own
                        # their SQLite writer and must not begin another one.
                        if self.engine.dialect.name == "sqlite":
                            self._begin_immediate(session)
                        else:
                            session.scalar(select(DispatcherLeaseRow).where(
                                DispatcherLeaseRow.lease_name == "dispatcher"
                            ).with_for_update())
                        current = now or (
                            session.scalar(select(func.clock_timestamp()))
                            if self.engine.dialect.name == "postgresql"
                            else datetime.now(timezone.utc)
                        )
                        expires = current + timedelta(seconds=ttl_s)
                        result = session.execute(
                            update(DispatcherLeaseRow)
                            .where(
                                DispatcherLeaseRow.lease_name == "dispatcher",
                                or_(
                                    DispatcherLeaseRow.owner_id == owner_id,
                                    DispatcherLeaseRow.expires_at <= current,
                                ),
                            )
                            .values(
                                owner_id=owner_id,
                                acquired_at=case(
                                    (DispatcherLeaseRow.owner_id == owner_id, DispatcherLeaseRow.acquired_at),
                                    else_=current,
                                ),
                                heartbeat_at=current,
                                expires_at=expires,
                            )
                        )
                        if result.rowcount == 0:
                            exists = session.get(DispatcherLeaseRow, "dispatcher")
                            if exists is not None:
                                return None
                            session.add(DispatcherLeaseRow(
                                lease_name="dispatcher",
                                owner_id=owner_id,
                                acquired_at=current,
                                heartbeat_at=current,
                                expires_at=expires,
                            ))
                    return DispatcherLease(
                        owner_id=owner_id,
                        acquired_at=current,
                        heartbeat_at=current,
                        expires_at=expires,
                    )
                except IntegrityError:
                    session.rollback()
                    return None

        return self._retry_sqlite_write(write)

    def release_dispatcher_lease(self, owner_id: str) -> bool:
        def write() -> bool:
            with self._session() as session, session.begin():
                result = session.execute(
                    delete(DispatcherLeaseRow).where(
                        DispatcherLeaseRow.lease_name == "dispatcher",
                        DispatcherLeaseRow.owner_id == owner_id,
                    )
                )
                return result.rowcount == 1

        return self._retry_sqlite_write(write)

    def get_dispatcher_lease(self) -> DispatcherLease | None:
        with self._session() as session:
            row = session.get(DispatcherLeaseRow, "dispatcher")
            if row is None:
                return None
            return DispatcherLease(
                owner_id=row.owner_id,
                acquired_at=row.acquired_at,
                heartbeat_at=row.heartbeat_at,
                expires_at=row.expires_at,
            )

    def put_dispatcher_status(self, status: DispatcherStatus) -> None:
        status.updated_at = datetime.now(timezone.utc)
        def write() -> None:
            with self._session() as session, session.begin():
                row = session.get(DispatcherStatusRow, "dispatcher") or DispatcherStatusRow(
                    status_id="dispatcher"
                )
                row.payload = _payload(status)
                session.add(row)

        self._retry_sqlite_write(write)

    def get_dispatcher_status(self) -> DispatcherStatus:
        with self._session() as session:
            row = session.get(DispatcherStatusRow, "dispatcher")
            return DispatcherStatus.model_validate(row.payload) if row else DispatcherStatus()

    def get_reconciliation_snapshot(self) -> dict[str, Any]:
        """Exact current proof with a rebuildable per-Job change projection.

        SQLite triggers track raw recovery writes. Changed Jobs are reconciled
        in one database snapshot; missing coverage falls back to the raw proof.
        Uncommitted writers never publish private state. Non-SQLite reads remain raw.
        """
        from .reconciliation_snapshot import reconciliation_snapshot

        if self.engine.dialect.name != "sqlite":
            with self._session() as session:
                projection = func.coalesce(JobRow.operational_payload, JobRow.payload)
                rows = session.execute(select(JobRow.job_id, JobRow.status, projection)
                    .where(func.cast(projection, String).contains("reconcile_pending"))).all()
            return reconciliation_snapshot(rows)

        cacheable = self._transaction_session() is None
        with self._session() as session:
            session.connection()
            with self._reconciliation_snapshot_lock:
                return self._reconciliation_read_projection.snapshot(session, cacheable=cacheable)

    def _lock_collection_recovery(self, session: Session) -> None:
        if self.engine.dialect.name == "sqlite":
            self._begin_immediate(session)
        else:
            session.execute(select(DispatcherStatusRow).where(
                DispatcherStatusRow.status_id == "dispatcher").with_for_update())

    @staticmethod
    def _collection_alert_rows(session: Session) -> list[AlertRow]:
        # Never use the UI's default 500-row page as a safety decision.
        return list(session.scalars(select(AlertRow).where(
            AlertRow.payload["kind"].as_string().in_(
                ["collection_failure", "collection_circuit_open"]))))

    @staticmethod
    def _collected_for_recovery(session: Session, attempt_ids: set[str]) -> dict[str, datetime]:
        collected: dict[str, datetime] = {}
        seen: set[str] = set()
        duplicates: set[str] = set()
        for job_id, payload in session.execute(select(JobRow.job_id, JobRow.operational_payload)):
            if payload is None:
                payload = _stored_job_operational_projection(session.scalar(
                    select(JobRow.payload).where(JobRow.job_id == job_id)) or {})
            for unit in payload.get("work_units", []):
                for attempt in unit.get("attempts", []):
                    identity = attempt.get("attempt_id")
                    if identity not in attempt_ids:
                        continue
                    if identity in seen:
                        duplicates.add(identity)
                    seen.add(identity)
                    stamp = _aware_datetime(attempt.get("collected_at"))
                    if stamp is not None and attempt.get("state") == "completed":
                        collected[identity] = stamp
        return {key: value for key, value in collected.items() if key not in duplicates}

    @staticmethod
    def _collection_proven(alert: AlertRecord, collected: dict[str, datetime], now: datetime) -> bool:
        stamp = collected.get(alert.subject_id)
        return bool(alert.subject_type == "attempt" and stamp is not None
                    and _aware_datetime(alert.last_seen_at) <= stamp <= now)

    @staticmethod
    def _collection_recovery_generation(session):
        """Trust the existing raw-write-aware epoch only with complete coverage."""
        from .reconciliation_read_projection import _HEADER, _PARAMS, ReconciliationReadProjection
        try:
            header = session.execute(text(_HEADER), _PARAMS).one_or_none()
        except OperationalError as exc:
            if "no such table" not in str(exc.orig):
                raise
            return None
        if header is None or not ReconciliationReadProjection._compatible(header):
            return None
        return (header.epoch, header.installation_id, header.schema_version)

    def _collection_recovery_read_proof(self, attempt_id=None, *, circuit=False):
        """Scan Job evidence before taking SQLite's single writer lock.

        Job triggers cover normal and raw SQL writes. An unchanged generation
        before/after the scan and again behind BEGIN IMMEDIATE proves that the
        evidence is still current. A concurrent change defers recovery; it never
        causes a full scan or an optimistic recovery inside the writer gate.
        Nested callers already hold that gate and defer until a later cycle.
        """
        if self._transaction_session() is not None:
            return None
        with self._session() as session:
            if circuit:
                row = session.get(DispatcherStatusRow, "dispatcher")
                if row is None or row.payload.get("blocked_reason") != "collection_circuit_breaker":
                    return None
            rows = [row for row in self._collection_alert_rows(session)
                    if (circuit or row.status != "resolved")
                    and (attempt_id is None or row.subject_id == attempt_id)]
            if not rows:
                return None
            generation = self._collection_recovery_generation(session)
            if generation is None:
                return None
            collected = self._collected_for_recovery(session, {row.subject_id for row in rows})
            if self._collection_recovery_generation(session) != generation:
                return None
            return generation, collected

    def latch_collection_circuit(self, alert_id: str) -> None:
        """Bind a global block to its exact persisted causes, preserving other controls."""
        def write() -> None:
            with self._session() as session, session.begin():
                self._lock_collection_recovery(session)
                alert = session.get(AlertRow, alert_id)
                if alert is None:
                    raise ValueError("collection circuit requires its persisted alert")
                row = session.get(DispatcherStatusRow, "dispatcher") or DispatcherStatusRow(status_id="dispatcher")
                status = DispatcherStatus.model_validate(row.payload) if row.payload else DispatcherStatus()
                if status.blocked_reason not in {"", "pending_reconciliation", "quarantined_reconciliation", "collection_circuit_breaker"}:
                    return  # An unrelated safety/control reason must never be overwritten.
                causes = status.collection_circuit_alert_ids if status.blocked_reason == "collection_circuit_breaker" else []
                unsettled = {a.alert_id for a in self._collection_alert_rows(session) if a.status != "resolved"}
                status.collection_circuit_alert_ids = sorted(set(causes) | unsettled | {alert_id})
                status.accepting_assignments = False
                status.control_mode = "drain"
                status.blocked_reason = "collection_circuit_breaker"
                status.auto_resume_allowed = False
                status.updated_at = datetime.now(timezone.utc)
                row.payload = _payload(status)
                session.add(row)
        self._retry_sqlite_write(write)

    def resolve_proven_collection_alerts(self, attempt_id: str | None = None) -> dict[str, list[str]]:
        """Resolve only failures followed by an actual persisted collection."""
        sqlite = self.engine.dialect.name == "sqlite"
        proof = self._collection_recovery_read_proof(attempt_id) if sqlite else None
        if sqlite and proof is None:
            return {}
        def write() -> dict[str, list[str]]:
            with self._session() as session, session.begin():
                self._lock_collection_recovery(session)
                if sqlite and self._collection_recovery_generation(session) != proof[0]:
                    return {}
                rows = [row for row in self._collection_alert_rows(session)
                        if row.status != "resolved" and (attempt_id is None or row.subject_id == attempt_id)]
                if not rows:
                    return {}
                collected = proof[1] if sqlite else self._collected_for_recovery(session, {row.subject_id for row in rows})
                now = datetime.now(timezone.utc)
                resolved: dict[str, list[str]] = {}
                for row in rows:
                    alert = AlertRecord.model_validate(row.payload)
                    if self._collection_proven(alert, collected, now):
                        alert.status = AlertStatus.RESOLVED
                        alert.resolved_at = now
                        row.status = "resolved"
                        row.payload = _payload(alert)
                        resolved.setdefault(alert.subject_id, []).append(alert.alert_id)
                return resolved
        return self._retry_sqlite_write(write)

    def resume_proven_collection_circuit(
        self, *, limit: int, externally_blocked: Callable[[], bool],
    ) -> DispatcherStatus | None:
        """Re-evaluate evidence and current operator intent in one write transaction.

        Legacy blocks without cause IDs need a recorded global circuit alert.
        Missing records are unknown, never a vacuous proof of successful recovery.
        """
        sqlite = self.engine.dialect.name == "sqlite"
        proof = self._collection_recovery_read_proof(circuit=True) if sqlite else None
        if sqlite and proof is None:
            return None
        def write() -> DispatcherStatus | None:
            with self._session() as session, session.begin():
                self._lock_collection_recovery(session)
                if sqlite and self._collection_recovery_generation(session) != proof[0]:
                    return None
                row = session.get(DispatcherStatusRow, "dispatcher")
                if row is None:
                    return None
                status = DispatcherStatus.model_validate(row.payload)
                if status.blocked_reason != "collection_circuit_breaker" or status.desired_state != "open" or limit <= 0:
                    return None
                alerts = [AlertRecord.model_validate(row.payload) for row in self._collection_alert_rows(session)]
                causes = set(status.collection_circuit_alert_ids)
                if not causes:
                    causes = {a.alert_id for a in alerts if a.kind == "collection_circuit_open"
                              and a.message == "repeated collection failure opened Dispatcher circuit"
                              and (status.last_recovered_at is None or
                                   _aware_datetime(a.last_seen_at) >= _aware_datetime(status.last_recovered_at))}
                if not causes or not causes.issubset({a.alert_id for a in alerts}):
                    return None
                episode_start = min(_aware_datetime(a.first_seen_at) for a in alerts if a.alert_id in causes)
                # UI resolution of a later, not-yet-escalated fault must not
                # remove it from this recovery episode's proof obligations.
                relevant = [a for a in alerts if a.alert_id in causes or a.status != "resolved"
                            or _aware_datetime(a.last_seen_at) >= episode_start]
                now = datetime.now(timezone.utc)
                collected = proof[1] if sqlite else self._collected_for_recovery(session, {a.subject_id for a in relevant})
                if any(a.status != "resolved" or not self._collection_proven(a, collected, now) for a in relevant):
                    return None
                count = status.collection_circuit_auto_resume_count
                reset_at = _aware_datetime(status.collection_circuit_auto_resume_reset_at)
                if reset_at is not None and reset_at > now:
                    return None
                if reset_at is None or now - reset_at >= timedelta(hours=24):
                    count = 0
                if count >= limit or externally_blocked():
                    return None
                status.accepting_assignments = True
                status.control_mode = "open"
                status.blocked_reason = ""
                status.auto_resume_allowed = True
                status.collection_circuit_auto_resume_count = count + 1
                status.collection_circuit_auto_resume_reset_at = now if count == 0 else reset_at
                status.collection_circuit_alert_ids = []
                status.last_recovered_at = now
                status.updated_at = now
                row.payload = _payload(status)
                return status
        return self._retry_sqlite_write(write)

    def put_dispatch_reservation(
        self, reservation: DispatchReservation, *, expected_job_revision: int | None = None,
        expected_state: str | None = None,
    ) -> bool:
        """Publish standby state and, for creation, consume its Job snapshot.

        Revision validation and advancement share the reservation transaction,
        so a concurrent Job envelope update cannot both commit the old standby
        and pass its own CAS. Scientific JSON and storage blobs stay untouched.
        Lifecycle updates omit ``expected_job_revision`` for compatibility.
        """
        reservation.updated_at = datetime.now(timezone.utc)
        def write() -> bool:
            with self._session() as session:
                try:
                    with session.begin():
                        if (expected_job_revision is not None or expected_state is not None) and self.engine.dialect.name == "sqlite":
                            self._begin_immediate(session)
                        guarded_row = None
                        if expected_state is not None:
                            guarded_row = session.scalar(select(DispatchReservationRow).where(
                                DispatchReservationRow.reservation_id == reservation.reservation_id,
                            ).with_for_update())
                            if guarded_row is None or guarded_row.state != expected_state:
                                return False
                        if expected_job_revision is not None:
                            job_row = session.scalar(select(JobRow).where(
                                JobRow.job_id == reservation.job_id,
                            ).with_for_update())
                            if job_row is None or job_row.revision != expected_job_revision:
                                raise RevisionConflictError(
                                    f"stale standby Job revision for {reservation.job_id}: "
                                    f"expected {expected_job_revision}"
                                )
                            projection = dict(job_row.operational_payload or
                                              _stored_job_operational_projection(job_row.payload))
                            next_revision = expected_job_revision + 1
                            projection.update(revision=next_revision,
                                              updated_at=reservation.updated_at.isoformat(),
                                              last_scheduled_at=reservation.updated_at.isoformat())
                            updated = session.execute(update(JobRow).where(
                                JobRow.job_id == reservation.job_id,
                                JobRow.revision == expected_job_revision,
                            ).values(revision=next_revision, updated_at=reservation.updated_at,
                                     operational_payload=projection))
                            if updated.rowcount != 1:
                                raise RevisionConflictError(
                                    f"stale standby Job revision for {reservation.job_id}"
                                )
                            replace_job_read_model(session, projection)
                        row = guarded_row if expected_state is not None else session.get(
                            DispatchReservationRow, reservation.reservation_id,
                        )
                        if row is None:
                            row = DispatchReservationRow(reservation_id=reservation.reservation_id)
                        row.active_key = reservation.active_key
                        row.machine_id = reservation.machine_id
                        row.job_id = reservation.job_id
                        row.work_unit_id = reservation.work_unit_id
                        row.state = reservation.state
                        row.updated_at = reservation.updated_at
                        row.payload = _payload(reservation)
                        session.add(row)
                    return True
                except IntegrityError:
                    session.rollback()
                    return False

        return self._retry_sqlite_write(write)

    def get_dispatch_reservation(self, reservation_id: str) -> DispatchReservation | None:
        with self._session() as session:
            row = session.get(DispatchReservationRow, reservation_id)
            return DispatchReservation.model_validate(row.payload) if row else None

    def list_dispatch_reservations(
        self,
        *,
        active_only: bool = False,
        machine_id: str | None = None,
        job_id: str | None = None,
    ) -> list[DispatchReservation]:
        with self._session() as session:
            statement = select(DispatchReservationRow)
            if active_only:
                statement = statement.where(DispatchReservationRow.active_key.is_not(None))
            if machine_id is not None:
                statement = statement.where(DispatchReservationRow.machine_id == machine_id)
            if job_id is not None:
                statement = statement.where(DispatchReservationRow.job_id == job_id)
            rows = session.scalars(
                statement.order_by(
                    DispatchReservationRow.machine_id,
                    DispatchReservationRow.updated_at,
                    DispatchReservationRow.reservation_id,
                )
            ).all()
            return [DispatchReservation.model_validate(row.payload) for row in rows]

    def put_enrollment(self, enrollment: EnrollmentRecord) -> None:
        with self._session() as session, session.begin():
            row = session.get(EnrollmentRow, enrollment.enrollment_id) or EnrollmentRow(
                enrollment_id=enrollment.enrollment_id
            )
            row.code_hash = enrollment.code_hash
            row.owner_user_id = enrollment.owner_user_id
            row.expires_at = enrollment.expires_at
            row.used = enrollment.used_at is not None
            row.payload = _payload(enrollment)
            session.add(row)

    def get_enrollment_by_code_hash(self, code_hash: str) -> EnrollmentRecord | None:
        with self._session() as session:
            row = session.scalar(select(EnrollmentRow).where(EnrollmentRow.code_hash == code_hash))
            return EnrollmentRecord.model_validate(row.payload) if row else None

    def consume_enrollment(
        self,
        enrollment: EnrollmentRecord,
        *,
        machine_id: str,
        hostname: str,
        capabilities: set[str],
        now: datetime | None = None,
    ) -> EnrollmentRecord | None:
        current = now or datetime.now(timezone.utc)
        enrollment.used_at = current
        enrollment.machine_id = machine_id
        enrollment.hostname = hostname
        enrollment.requested_capabilities = set(capabilities)
        with self._session() as session, session.begin():
            result = session.execute(
                update(EnrollmentRow)
                .where(
                    EnrollmentRow.enrollment_id == enrollment.enrollment_id,
                    EnrollmentRow.code_hash == enrollment.code_hash,
                    EnrollmentRow.used.is_(False),
                    EnrollmentRow.expires_at > current,
                )
                .values(used=True, payload=_payload(enrollment))
            )
            return enrollment if result.rowcount == 1 else None

    def list_enrollments(self, *, owner_user_id: str | None = None) -> list[EnrollmentRecord]:
        statement = select(EnrollmentRow).order_by(EnrollmentRow.expires_at.desc())
        if owner_user_id is not None:
            statement = statement.where(EnrollmentRow.owner_user_id == owner_user_id)
        with self._session() as session:
            return [EnrollmentRecord.model_validate(row.payload) for row in session.scalars(statement)]

    def recent_resource_usage(self, *, hours: int = 24, now: datetime | None = None) -> dict:
        """One operational scan; clip each Attempt to the real time window."""
        from .dispatch_policy import usage_from_projections
        current = now or datetime.now(timezone.utc)
        threshold = current - timedelta(hours=hours)
        statement = select(JobRow.operational_payload).where(or_(
            JobRow.updated_at >= threshold,
            JobRow.status.in_(["queued", "running", "failed_retriable"]),
        ))
        with self._session() as session:
            projections = session.scalars(statement.execution_options(stream_results=True, yield_per=32))
            return usage_from_projections(projections, now=current, hours=hours)

    def recent_usage_seconds(self, user_id: str, *, hours: int = 24) -> float:
        return self.recent_resource_usage(hours=hours)["users"].get(user_id, {}).get("wall_seconds", 0.0)

    def recent_project_usage_seconds(self, project_id: str, *, hours: int = 24) -> float:
        return self.recent_resource_usage(hours=hours)["projects"].get(project_id, {}).get("wall_seconds", 0.0)

    def append_event(self, event: AuditEvent) -> None:
        for attempt in range(8):
            try:
                with self._session() as session, session.begin():
                    next_value = session.execute(
                        update(EventSequenceRow)
                        .where(EventSequenceRow.sequence_id == "global")
                        .values(next_sequence=EventSequenceRow.next_sequence + 1)
                        .returning(EventSequenceRow.next_sequence)
                    ).scalar_one()
                    event.sequence = next_value - 1
                    session.add(EventRow(
                        event_id=event.event_id,
                        event_type=event.event_type,
                        subject_type=event.subject_type,
                        subject_id=event.subject_id,
                        created_at=event.created_at,
                        sequence=event.sequence,
                        payload=_payload(event),
                    ))
                return
            except (OperationalError, sqlite3.OperationalError) as exc:
                if self._transaction_session() is not None:
                    raise
                if (
                    self.engine.dialect.name != "sqlite"
                    or "locked" not in str(exc).lower()
                    or attempt == 7
                ):
                    raise
                time.sleep(min(0.05 * (2 ** attempt), 1.0))
            except IntegrityError as exc:
                if self._transaction_session() is not None:
                    raise
                if "audit_events.sequence" not in str(exc) or attempt == 7:
                    raise
                def repair_sequence() -> None:
                    with self._session() as session, session.begin():
                        next_sequence = int(session.scalar(select(func.max(EventRow.sequence))) or 0) + 1
                        session.execute(
                            update(EventSequenceRow)
                            .where(
                                EventSequenceRow.sequence_id == "global",
                                EventSequenceRow.next_sequence < next_sequence,
                            )
                            .values(next_sequence=next_sequence)
                        )

                self._retry_sqlite_write(repair_sequence)

    def put_artifact_manifest(self, manifest: ArtifactManifest) -> None:
        def write() -> None:
            with self._session() as session, session.begin():
                # Serialize before reading so concurrent collection does not
                # upgrade a stale SQLite snapshot or race the first insert.
                if self.engine.dialect.name == "sqlite":
                    self._begin_immediate(session)
                row = session.get(ArtifactRow, manifest.work_unit_id) or ArtifactRow(
                    work_unit_id=manifest.work_unit_id,
                    job_id=manifest.job_id,
                    created_at=manifest.created_at,
                )
                row.job_id = manifest.job_id
                row.created_at = manifest.created_at
                row.payload = _payload(manifest)
                session.add(row)

        self._retry_sqlite_write(write)

    def get_artifact_manifest(self, work_unit_id: str) -> ArtifactManifest | None:
        with self._session() as session:
            row = session.get(ArtifactRow, work_unit_id)
            return ArtifactManifest.model_validate(row.payload) if row else None

    def list_artifact_manifests(self, job_id: str) -> list[ArtifactManifest]:
        statement = select(ArtifactRow).where(ArtifactRow.job_id == job_id).order_by(ArtifactRow.created_at)
        with self._session() as session:
            return [ArtifactManifest.model_validate(row.payload) for row in session.scalars(statement)]

    def put_origin_import_receipt(self, receipt: OriginImportReceipt) -> None:
        with self._session() as session, session.begin():
            row = session.get(OriginImportReceiptRow, receipt.job_id) or OriginImportReceiptRow(
                job_id=receipt.job_id,
                dataset_id=receipt.dataset_id,
                imported_at=receipt.imported_at,
            )
            row.dataset_id = receipt.dataset_id
            row.imported_at = receipt.imported_at
            row.payload = _payload(receipt)
            session.add(row)

    def get_origin_import_receipt(self, job_id: str) -> OriginImportReceipt | None:
        with self._session() as session:
            row = session.get(OriginImportReceiptRow, job_id)
            return OriginImportReceipt.model_validate(row.payload) if row else None

    @_request_cached_metadata
    def get_feature_settings(self) -> FeatureSettings:
        with self._session() as session:
            row = session.get(FeatureSettingsRow, "global")
            return FeatureSettings.model_validate(row.payload) if row else FeatureSettings()

    def put_feature_settings(self, settings: FeatureSettings, *, preserve_scheduling: bool = True) -> None:
        """Keep dedicated CAS scheduling state across legacy settings writers."""
        def write() -> None:
            with self._session() as session, session.begin():
                if self.engine.dialect.name == "sqlite":
                    self._begin_immediate(session)
                row = session.scalar(select(FeatureSettingsRow).where(
                    FeatureSettingsRow.settings_id == "global").with_for_update())
                if row is not None and preserve_scheduling:
                    current = FeatureSettings.model_validate(row.payload)
                    for name in ("scheduling_policy", "scheduling_revision", "scheduling_confirmation"):
                        setattr(settings, name, getattr(current, name))
                row = row or FeatureSettingsRow(settings_id="global")
                row.payload = _payload(settings)
                session.add(row)
        self._retry_sqlite_write(write)

    def put_machine_execution_config(self, config: MachineExecutionConfig, *, touch: bool = True) -> None:
        if touch:
            config.updated_at = datetime.now(timezone.utc)
        with self._session() as session, session.begin():
            if config.enabled and session.get(MemberRetirementRow, config.machine_id) is not None:
                raise ValueError("member retirement remains active; execution cannot be reenabled")
            row = session.get(MachineExecutionConfigRow, config.machine_id) or MachineExecutionConfigRow(
                machine_id=config.machine_id
            )
            row.payload = _payload(config)
            session.add(row)

    @_request_cached_metadata
    def get_machine_execution_config(self, machine_id: str) -> MachineExecutionConfig | None:
        with self._session() as session:
            row = session.get(MachineExecutionConfigRow, machine_id)
            return MachineExecutionConfig.model_validate(row.payload) if row else None

    @_request_cached_metadata
    def list_machine_execution_configs(self) -> list[MachineExecutionConfig]:
        with self._session() as session:
            return [
                MachineExecutionConfig.model_validate(row.payload)
                for row in session.scalars(select(MachineExecutionConfigRow))
            ]

    def put_remote_run(self, run: RemoteRunRecord) -> None:
        run.updated_at = datetime.now(timezone.utc)
        def write() -> None:
            with self._session() as session, session.begin():
                row = session.get(RemoteRunRow, run.external_run_id) or RemoteRunRow(
                    external_run_id=run.external_run_id
                )
                row.machine_id = run.machine_id
                row.work_unit_id = run.work_unit_id
                row.state = run.state.value
                row.updated_at = run.updated_at
                row.payload = _payload(run)
                session.add(row)

        self._retry_sqlite_write(write)

    def get_remote_run(self, external_run_id: str) -> RemoteRunRecord | None:
        with self._session() as session:
            row = session.get(RemoteRunRow, external_run_id)
            return RemoteRunRecord.model_validate(row.payload) if row else None

    def list_remote_runs(self, machine_id: str | None = None) -> list[RemoteRunRecord]:
        statement = select(RemoteRunRow).order_by(RemoteRunRow.updated_at.desc())
        if machine_id is not None:
            statement = statement.where(RemoteRunRow.machine_id == machine_id)
        with self._session() as session:
            return [RemoteRunRecord.model_validate(row.payload) for row in session.scalars(statement)]

    def remote_run_attempt_index(
        self,
        job_ids: Iterable[str],
    ) -> dict[str, tuple[str, bool]]:
        """Map remote run IDs to current Attempt state without hydrating Job payloads."""
        selected_job_ids = sorted({str(job_id) for job_id in job_ids if job_id})
        if not selected_job_ids:
            return {}

        projections: list[dict[str, Any]] = []
        missing_job_ids: list[str] = []
        with self._session() as session:
            rows = session.execute(
                select(JobRow.job_id, JobRow.operational_payload).where(
                    JobRow.job_id.in_(selected_job_ids)
                )
            ).all()
            for row in rows:
                if row.operational_payload is None:
                    missing_job_ids.append(str(row.job_id))
                else:
                    projections.append(row.operational_payload)
            if missing_job_ids:
                legacy_rows = session.execute(
                    select(JobRow.payload).where(JobRow.job_id.in_(missing_job_ids))
                ).all()
                projections.extend(
                    _stored_job_operational_projection(row.payload or {})
                    for row in legacy_rows
                )

        result: dict[str, tuple[str, bool]] = {}
        for projection in projections:
            for unit in projection.get("work_units") or []:
                attempts = unit.get("attempts") or []
                for index, attempt in enumerate(attempts):
                    external_run_id = attempt.get("external_run_id")
                    state = attempt.get("state")
                    if external_run_id and state:
                        result[str(external_run_id)] = (
                            str(state),
                            index == len(attempts) - 1,
                        )
        return result

    def put_ssh_acceptance_run(self, run: SshAcceptanceRun) -> None:
        run.updated_at = datetime.now(timezone.utc)
        with self._session() as session, session.begin():
            row = session.get(SshAcceptanceRow, run.run_id) or SshAcceptanceRow(
                run_id=run.run_id,
                created_at=run.created_at,
            )
            row.status = run.status.value
            row.created_at = run.created_at
            row.payload = _payload(run)
            session.add(row)

    def get_ssh_acceptance_run(self, run_id: str) -> SshAcceptanceRun | None:
        with self._session() as session:
            row = session.get(SshAcceptanceRow, run_id)
            return SshAcceptanceRun.model_validate(row.payload) if row else None

    def list_ssh_acceptance_runs(self) -> list[SshAcceptanceRun]:
        statement = select(SshAcceptanceRow).order_by(SshAcceptanceRow.created_at.desc())
        with self._session() as session:
            return [SshAcceptanceRun.model_validate(row.payload) for row in session.scalars(statement)]

    def put_machine_preflight_run(self, run: MachinePreflightRun) -> None:
        run.updated_at = datetime.now(timezone.utc)
        with self._session() as session, session.begin():
            row = session.get(MachinePreflightRow, run.run_id) or MachinePreflightRow(
                run_id=run.run_id,
                machine_id=run.machine_id,
                created_at=run.created_at,
            )
            row.machine_id = run.machine_id
            row.status = run.status.value
            row.created_at = run.created_at
            row.payload = _payload(run)
            session.add(row)

    def get_machine_preflight_run(self, run_id: str) -> MachinePreflightRun | None:
        with self._session() as session:
            row = session.get(MachinePreflightRow, run_id)
            return MachinePreflightRun.model_validate(row.payload) if row else None

    def list_machine_preflight_runs(self, machine_id: str | None = None) -> list[MachinePreflightRun]:
        statement = select(MachinePreflightRow).order_by(MachinePreflightRow.created_at.desc())
        if machine_id is not None:
            statement = statement.where(MachinePreflightRow.machine_id == machine_id)
        with self._session() as session:
            return [MachinePreflightRun.model_validate(row.payload) for row in session.scalars(statement)]

    def list_events(
        self,
        limit: int = 200,
        *,
        subject_type: str | None = None,
        subject_id: str | None = None,
        event_type: str | None = None,
        before_sequence: int | None = None,
    ) -> list[AuditEvent]:
        statement = select(EventRow)
        if subject_type is not None:
            statement = statement.where(EventRow.subject_type == subject_type)
        if subject_id is not None:
            statement = statement.where(EventRow.subject_id == subject_id)
        if event_type is not None:
            statement = statement.where(EventRow.event_type == event_type)
        if before_sequence is not None:
            statement = statement.where(EventRow.sequence < before_sequence)
        statement = statement.order_by(EventRow.sequence.desc()).limit(limit)
        with self._session() as session:
            return [AuditEvent.model_validate(row.payload) for row in session.scalars(statement)]

    def latest_event_sequence(self) -> int:
        with self._session() as session:
            return int(session.scalar(select(func.max(EventRow.sequence))) or 0)

    def list_events_after(self, sequence: int, limit: int = 1000) -> list[AuditEvent]:
        statement = (
            select(EventRow)
            .where(EventRow.sequence > sequence)
            .order_by(EventRow.sequence)
            .limit(limit)
        )
        with self._session() as session:
            return [AuditEvent.model_validate(row.payload) for row in session.scalars(statement)]

    @staticmethod
    def _demo_object_ids(session: Session) -> dict[str, list[str]]:
        expected_machine_ids = {f"sim-worker-{index:02d}" for index in range(1, 7)}
        machine_ids = [
            row.machine_id for row in session.scalars(select(MachineRow)).all()
            if row.machine_id in expected_machine_ids
        ]
        job_ids = [
            row.job_id for row in session.scalars(select(JobRow)).all()
            if row.job_id.startswith("sim-job-")
        ]
        artifact_ids = [
            row.work_unit_id for row in session.scalars(select(ArtifactRow)).all()
            if row.job_id in job_ids
        ]
        credential_ids = [
            row.credential_id for row in session.scalars(select(MachineCredentialRow)).all()
            if row.machine_id in expected_machine_ids
        ]
        approval_ids = [
            row.approval_id for row in session.scalars(select(ApprovalRow)).all()
            if row.machine_id in expected_machine_ids
        ]
        metric_ids = [
            row.sample_id for row in session.scalars(select(MetricSampleRow)).all()
            if row.machine_id in expected_machine_ids
        ]
        remote_run_ids = []
        for row in session.scalars(select(RemoteRunRow)).all():
            run = RemoteRunRecord.model_validate(row.payload)
            if run.machine_id in expected_machine_ids or run.job_id in job_ids:
                remote_run_ids.append(row.external_run_id)
        demo_subjects = set(expected_machine_ids).union(job_ids, artifact_ids, approval_ids)
        demo_subjects.update({"demo-simulator-project", "demo-member"})
        event_ids = []
        for row in session.scalars(select(EventRow)).all():
            event = AuditEvent.model_validate(row.payload)
            if (
                event.actor_id == "demo-simulator"
                or event.subject_id in demo_subjects
                or event.details.get("machine_id") in expected_machine_ids
                or event.details.get("job_id") in job_ids
            ):
                event_ids.append(row.event_id)
        non_demo_user_refs = any(
            row.user_id == "demo-member" and row.job_id not in job_ids
            for row in session.scalars(select(JobRow)).all()
        ) or any(
            row.owner_user_id == "demo-member" and row.machine_id not in expected_machine_ids
            for row in session.scalars(select(MachineRow)).all()
        ) or any(
            ProjectGrant.model_validate(row.payload).owner_user_id == "demo-member"
            and row.project_id != "demo-simulator-project"
            for row in session.scalars(select(ProjectGrantRow)).all()
        )
        user_ids = [] if non_demo_user_refs or session.get(UserRow, "demo-member") is None else ["demo-member"]
        token_ids = [
            row.token_id for row in session.scalars(select(TokenRow)).all()
            if row.user_id in user_ids
        ]
        return {
            "machines": sorted(machine_ids),
            "policies": sorted(
                row.machine_id for row in session.scalars(select(PolicyRow)).all()
                if row.machine_id in expected_machine_ids
            ),
            "operational_statuses": sorted(
                row.machine_id for row in session.scalars(select(MachineOperationalStatusRow)).all()
                if row.machine_id in expected_machine_ids
            ),
            "execution_configs": sorted(
                row.machine_id for row in session.scalars(select(MachineExecutionConfigRow)).all()
                if row.machine_id in expected_machine_ids
            ),
            "credentials": sorted(credential_ids),
            "metrics": sorted(metric_ids),
            "approvals": sorted(approval_ids),
            "jobs": sorted(job_ids),
            "artifacts": sorted(artifact_ids),
            "remote_runs": sorted(remote_run_ids),
            "events": sorted(event_ids),
            "projects": ["demo-simulator-project"] if session.get(ProjectGrantRow, "demo-simulator-project") else [],
            "users": user_ids,
            "tokens": sorted(token_ids),
        }

    @staticmethod
    def _demo_preview_from_ids(object_ids: dict[str, list[str]]) -> DemoCleanupPreview:
        import hashlib
        import json

        canonical = json.dumps(object_ids, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return DemoCleanupPreview(
            confirmation_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            counts={kind: len(ids) for kind, ids in object_ids.items()},
            object_ids=object_ids,
        )

    def preview_demo_cleanup(self) -> DemoCleanupPreview:
        with self._session() as session:
            return self._demo_preview_from_ids(self._demo_object_ids(session))

    def confirm_demo_cleanup(self, confirmation_hash: str) -> DemoCleanupPreview:
        row_types = {
            "machines": (MachineRow, MachineRow.machine_id),
            "policies": (PolicyRow, PolicyRow.machine_id),
            "operational_statuses": (MachineOperationalStatusRow, MachineOperationalStatusRow.machine_id),
            "execution_configs": (MachineExecutionConfigRow, MachineExecutionConfigRow.machine_id),
            "credentials": (MachineCredentialRow, MachineCredentialRow.credential_id),
            "metrics": (MetricSampleRow, MetricSampleRow.sample_id),
            "approvals": (ApprovalRow, ApprovalRow.approval_id),
            "jobs": (JobRow, JobRow.job_id),
            "artifacts": (ArtifactRow, ArtifactRow.work_unit_id),
            "remote_runs": (RemoteRunRow, RemoteRunRow.external_run_id),
            "events": (EventRow, EventRow.event_id),
            "projects": (ProjectGrantRow, ProjectGrantRow.project_id),
            "users": (UserRow, UserRow.user_id),
            "tokens": (TokenRow, TokenRow.token_id),
        }
        with self._session() as session, session.begin():
            preview = self._demo_preview_from_ids(self._demo_object_ids(session))
            if preview.confirmation_hash != confirmation_hash:
                raise ValueError("demo cleanup preview changed; request a new preview")
            job_ids = preview.object_ids.get("jobs") or []
            if job_ids:
                for projection_row in (AttemptReadRow, UnitReadRow, JobReadRow):
                    session.execute(delete(projection_row).where(projection_row.job_id.in_(job_ids)))
            for kind, ids in preview.object_ids.items():
                if ids:
                    row_type, column = row_types[kind]
                    session.execute(delete(row_type).where(column.in_(ids)))
            return preview
