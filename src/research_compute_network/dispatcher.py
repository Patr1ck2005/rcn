"""Single-active dispatcher process for fixed-profile scheduler adapters."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .failure_diagnostics import (
    is_collection_integrity_failure,
    is_deterministic_scientific_failure,
    is_memory_exhaustion_failure,
    is_comsol_disconnect_failure,
    is_native_file_io_failure,
    is_ssh_transport_failure,
    is_storage_exhaustion_failure,
    is_worker_termination_failure,
    safe_failure_reason,
    timeout_evidence,
)
from .hashing import sha256_file
from .control_transactions import atomic_metadata
from .origin import OriginSpool
from .models import (
    AlertRecord,
    AlertSeverity,
    AlertStatus,
    ArtifactManifest,
    Assignment,
    DispatchReservation,
    DispatcherLease,
    DispatcherPhase,
    DispatcherStatus,
    FailureClass,
    JobEnvelope,
    JobStatus,
    RemoteRunRecord,
    RemoteRunState,
    WorkUnit,
    WorkUnitStatus,
)
from .repository import MetadataRepository
from .storage_roots import StorageRootError
from .volume_budget import VolumeHolderBusy
from .schedulers.base import PreLaunchSubmissionError, SubmissionUncertainError, SchedulerAdapter
from .schedulers.ssh import CollectionCapacityUnavailable, SshTransportUnavailableError
from .service import (
    NetworkService,
    PACKAGE_VERSION,
    PROTOCOL_VERSION,
)


AdapterProvider = Callable[[str], SchedulerAdapter]
StagingProvider = Callable[[JobEnvelope, WorkUnit, str], Path]


class _SubmissionAborted(Exception):
    """The aggregate changed state before a pending submission could start."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def _attempt_observation_is_current(unit: WorkUnit, attempt) -> bool:
    """Fence a retired or superseded attempt inside the aggregate transaction.

    Remote I/O may finish after an administrator abandons an unreachable run.
    Its observation must never resurrect that attempt or modify its successor.
    """
    return bool(
        unit.attempts
        and unit.attempts[-1].attempt_id == attempt.attempt_id
        and attempt.state != "abandoned"
    )

def _cancellation_won(job: JobEnvelope, unit: WorkUnit, attempt) -> bool:
    """Return whether cancellation or retirement beats this observation."""
    return bool(
        not _attempt_observation_is_current(unit, attempt)
        or job.status == JobStatus.CANCELLED
        or unit.status == WorkUnitStatus.CANCELLED
        or attempt.state in {"cancel_pending", "cancelled"}
        or attempt.cancel_requested_at is not None
    )


def classify_remote_failure(run: RemoteRunRecord) -> FailureClass:
    if run.failure_class is not None:
        return run.failure_class
    message = run.message.lower()
    resource_markers = (
        "out of memory",
        "not enough memory",
        "memory limit",
        "no space left",
        "disk full",
        "disk quota",
    )
    if is_memory_exhaustion_failure(message) or is_storage_exhaustion_failure(message) or any(marker in message for marker in resource_markers):
        return FailureClass.RESOURCE_EXHAUSTION
    if is_native_file_io_failure(message):
        return FailureClass.INFRASTRUCTURE
    if is_worker_termination_failure(run.message):
        # A deterministic console-termination exit code (e.g. 0xC000013A) means
        # the worker's transport session died underneath it before any
        # diagnostic was written. The scientific payload never decided the
        # outcome, so this is bounded-retry infrastructure, not unknown.
        return FailureClass.INFRASTRUCTURE
    if is_deterministic_scientific_failure(run.message):
        return FailureClass.SCIENTIFIC_INPUT
    if is_comsol_disconnect_failure(message):
        return FailureClass.UNKNOWN
    infrastructure_markers = (
        "ssh",
        "network",
        "transport",
        "host unreachable",
        "connection",
        "file handle",
        "interrupted",
    )
    scientific_markers = ("invalid input", "model error", "solver failed", "scientific")
    if any(marker in message for marker in infrastructure_markers):
        return FailureClass.INFRASTRUCTURE
    if any(marker in message for marker in scientific_markers):
        return FailureClass.SCIENTIFIC_INPUT
    return FailureClass.UNKNOWN


def classify_submission_failure(exc: Exception) -> FailureClass:
    """Classify adapter submission failures without treating every ValueError as scientific.

    Bundle staging, Origin handoff, runtime allowlists, and transport are deployment
    failures even when an adapter uses ``ValueError`` to report them.  Only explicit
    model/spec/solver language is terminal scientific input.
    """
    message = str(exc).lower()
    infrastructure_markers = (
        "origin handoff",
        "allowlisted",
        "allowlist",
        "sealed bundle",
        "runtime",
        "bundle rejected",
        "transport",
        "staging",
        "ssh",
        "connection",
        "host unreachable",
        "dispatcher",
    )
    if any(marker in message for marker in infrastructure_markers):
        return FailureClass.INFRASTRUCTURE
    scientific_markers = (
        "invalid input",
        "invalid scan spec",
        "invalid recipe",
        "unsupported recipe",
        "model error",
        "solver failed",
        "scientific input",
    )
    if any(marker in message for marker in scientific_markers):
        return FailureClass.SCIENTIFIC_INPUT
    # An unclassified adapter-side submission error has not established a
    # scientific failure and must remain recoverable for operator diagnosis.
    return FailureClass.INFRASTRUCTURE


def _is_transport_collection_failure(exc: BaseException) -> bool:
    """Return whether bounded evidence proves the machine transport failed.

    A typed SSH transport failure, an SSH/SCP child timeout, or a known
    connection diagnostic is machine-scoped in the absence of contradictory
    integrity evidence. Local timeouts and unknown diagnostics are not proof
    that a machine connection failed and retain the conservative global scope.
    """
    # A local hashing/validation timeout does not establish a failed machine.
    if is_collection_integrity_failure(str(exc)):
        return False
    if isinstance(exc, SshTransportUnavailableError):
        return True
    if isinstance(exc, subprocess.TimeoutExpired):
        command = exc.cmd
        executable = command[0] if isinstance(command, (list, tuple)) and command else command
        executable = str(executable).replace('\\', '/').rsplit('/', 1)[-1].lower()
        return executable in {'ssh', 'ssh.exe', 'scp', 'scp.exe', 'sftp', 'sftp.exe'}
    return is_ssh_transport_failure(str(exc))


class Dispatcher:
    def __init__(
        self,
        service: NetworkService,
        adapter_provider: AdapterProvider,
        *,
        owner_id: str | None = None,
        staging_provider: StagingProvider | None = None,
        origin_spool: OriginSpool | None = None,
        lease_ttl_s: int = 30,
        reconcile_grace_s: int = 90,
        max_assignments_per_cycle: int = 16,
        max_concurrent_collections: int = 3,
        max_concurrent_submissions: int = 4,
        max_concurrent_preparations: int = 4,
        max_concurrent_reconciliations: int = 5,
        standby_activation_retry_after_s: int = 30,
        max_standby_activation_retries: int = 2,
        standby_activation_stall_after_s: int = 180,
        collection_circuit_window_s: int = 300,
        collection_circuit_failure_limit: int = 2,
        collection_circuit_auto_resume_limit: int = 2,
        nonblocking_io: bool = False,
        io_stop_event: threading.Event | None = None,
    ) -> None:
        self.service = service
        self.repository: MetadataRepository = service.repository
        self.adapter_provider = adapter_provider
        self.owner_id = owner_id or f"dispatcher-{uuid.uuid4().hex[:12]}"
        self.staging_provider = staging_provider
        self.origin_spool = origin_spool
        self.lease_ttl_s = lease_ttl_s
        self.reconcile_grace_s = reconcile_grace_s
        self.max_assignments_per_cycle = max_assignments_per_cycle
        self.max_concurrent_collections = max_concurrent_collections
        self.max_concurrent_submissions = max(1, max_concurrent_submissions)
        self.max_concurrent_preparations = max(1, max_concurrent_preparations)
        self.max_concurrent_reconciliations = max(1, max_concurrent_reconciliations)
        self.standby_activation_retry_after_s = max(5, standby_activation_retry_after_s)
        self.max_standby_activation_retries = max(0, min(3, max_standby_activation_retries))
        self.standby_activation_stall_after_s = max(
            self.standby_activation_retry_after_s,
            standby_activation_stall_after_s,
        )
        self.collection_circuit_window_s = collection_circuit_window_s
        self.collection_circuit_failure_limit = collection_circuit_failure_limit
        self.collection_circuit_auto_resume_limit = max(0, collection_circuit_auto_resume_limit)
        self.status = DispatcherStatus(
            owner_id=self.owner_id,
            phase=DispatcherPhase.STARTING,
            package_version=PACKAGE_VERSION,
            protocol_version=PROTOCOL_VERSION,
            runtime_version=service.runtime_policy.stable_runtime_version,
        )
        self._held_lease = False
        self._lease_lost = False
        self._lease_lock = threading.Lock()
        self._lease_deadline: float | None = None
        self._lease_expires_at: datetime | None = None
        self._collection_pool = ThreadPoolExecutor(
            max_workers=max_concurrent_collections,
            thread_name_prefix="rcn-collect",
        )
        self._submission_pool = ThreadPoolExecutor(
            max_workers=self.max_concurrent_submissions,
            thread_name_prefix="rcn-submit",
        )
        self._preparation_pool = ThreadPoolExecutor(
            max_workers=self.max_concurrent_preparations,
            thread_name_prefix="rcn-prepare",
        )
        self._reconciliation_pool = ThreadPoolExecutor(
            max_workers=self.max_concurrent_reconciliations,
            thread_name_prefix="rcn-reconcile",
        )
        self._collection_futures: dict[tuple[str, str, str], tuple[str, Future[bool]]] = {}
        self._collection_lock = threading.Lock()
        self._collection_storage_retry_after: dict[tuple[str, str, str], float] = {}
        self._reported_unready_bundles: set[tuple[str, str, str]] = set()
        self._wake_event = threading.Event()
        self.io_stop_event = io_stop_event or threading.Event()
        self._stopping = False
        from .dispatch_pipeline import DispatchPipeline
        self._pipeline = DispatchPipeline(self) if nonblocking_io else None

    def wake(self) -> None:
        """Request an immediate reconciliation on the next dispatcher loop."""
        self._wake_event.set()

    def _accept_dispatcher_lease(self, lease: DispatcherLease | None, *, source: str = "receipt") -> bool:
        """Apply every lease receipt without reviving an already fenced process."""
        reason = None
        event = None
        accepted = False
        expires_at = None
        new_remaining = None
        previous_wall_remaining = None
        with self._lease_lock:
            if self._lease_lost:
                return False
            checked_at = time.monotonic()
            deadline = self._lease_deadline
            if lease is None:
                if self._held_lease:
                    reason = "renewal_not_owned"
            elif lease.owner_id != self.owner_id:
                reason = "receipt_owner_mismatch"
            else:
                # The two clock reads bracket the wall-clock conversion. A
                # delayed conversion must not revive a gap in the old lease.
                received_at = time.monotonic()
                expires_at = _aware(lease.expires_at)
                wall_now = _utc_now()
                candidate_deadline = received_at + (expires_at - wall_now).total_seconds()
                checked_at = time.monotonic()
                new_remaining = candidate_deadline - checked_at
                previous_wall_remaining = (self._lease_expires_at - wall_now).total_seconds() if self._lease_expires_at is not None else None
                if deadline is not None and checked_at >= deadline:
                    reason = "previous_deadline_expired"
                elif previous_wall_remaining is not None and previous_wall_remaining <= 0:
                    reason = "previous_wall_expiry_elapsed"
                elif self._lease_expires_at is not None and expires_at <= self._lease_expires_at:
                    # Ignore an old receipt only while the newer confirmed
                    # lease remains valid on both clocks. Never reproject it.
                    accepted, event, reason = True, "lease_receipt_ignored", "receipt_expiry_not_newer"
                elif candidate_deadline <= checked_at:
                    reason = "initial_receipt_expired" if deadline is None else "new_receipt_expired"
                else:
                    self._held_lease = True
                    self._lease_expires_at = expires_at
                    # A genuinely newer grant may project earlier after a
                    # forward wall-clock adjustment. Keep the shorter bound.
                    self._lease_deadline = candidate_deadline
                    accepted = True
            previous_remaining = None if deadline is None else deadline - checked_at
            if reason is not None and not accepted:
                self._fence_dispatcher_lease_locked()
                event = "lease_fenced"
        if event is not None:
            self._lease_diagnostic(event, source=source, reason=reason,
                observed_monotonic=checked_at, previous_remaining_s=previous_remaining,
                previous_wall_remaining_s=previous_wall_remaining, new_remaining_s=new_remaining,
                receipt_expires_at=expires_at.isoformat() if expires_at is not None else None)
        return accepted

    def _fence_dispatcher_lease_locked(self) -> None:
        """Caller owns the memory-only lease lock; this fence is terminal."""
        self._lease_lost = True
        self.io_stop_event.set()
        self.status.accepting_assignments = False

    def _lease_diagnostic(self, event: str, **safe_values) -> None:
        """Independent process log, outside the lease lock and metadata DB."""
        try:
            sys.stderr.write(json.dumps({"event": event, "utc": datetime.now(timezone.utc).isoformat(),
                "monotonic": time.monotonic(), "thread": threading.current_thread().name,
                **safe_values}, sort_keys=True) + "\n")
            sys.stderr.flush()
        except Exception:
            # A log failure cannot undo a fence or replace the original error.
            pass

    def _acquire_dispatcher_lease(self, source: str) -> DispatcherLease | None:
        started = time.monotonic()
        error_type = None
        sqlite_errorcode = None
        sqlite_errorname = None
        lease = None
        with self._lease_lock:
            previous_remaining = None if self._lease_deadline is None else self._lease_deadline - started
        if source == "heartbeat":
            self._lease_diagnostic("lease_acquire_start", source=source,
                observed_monotonic=started, previous_remaining_s=previous_remaining)
        try:
            lease = self.repository.acquire_dispatcher_lease(self.owner_id, ttl_s=self.lease_ttl_s)
            return lease
        except Exception as exc:
            error_type = type(exc).__name__
            try:
                original = getattr(exc, "orig", exc)
                code = getattr(original, "sqlite_errorcode", None)
                name = getattr(original, "sqlite_errorname", None)
                if type(code) is int and 0 <= code <= 2147483647:
                    sqlite_errorcode = code
                if (isinstance(name, str) and name.startswith("SQLITE_") and len(name) <= 64
                        and all(character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789" for character in name)):
                    sqlite_errorname = name
            except Exception:
                pass
            raise
        finally:
            finished = time.monotonic()
            elapsed = max(0.0, finished - started)
            with self._lease_lock:
                previous_remaining = None if self._lease_deadline is None else self._lease_deadline - finished
            if source == "heartbeat" or error_type is not None or elapsed >= self.lease_ttl_s / 3:
                self._lease_diagnostic("lease_acquire_end", source=source,
                    observed_monotonic=finished, previous_remaining_s=previous_remaining,
                    elapsed_s=round(elapsed, 6), error_type=error_type, granted=lease is not None,
                    sqlite_errorcode=sqlite_errorcode, sqlite_errorname=sqlite_errorname,
                    receipt_expires_at=lease.expires_at.isoformat() if lease is not None else None,
                    receipt_remaining_wall_s=(_aware(lease.expires_at) - _utc_now()).total_seconds() if lease is not None else None)

    def run_cycle(self) -> bool:
        lease = self._acquire_dispatcher_lease("cycle_start")
        if not self._accept_dispatcher_lease(lease, source="cycle_start"):
            self.status.phase = DispatcherPhase.STANDBY
            self.status.heartbeat_at = _utc_now()
            return False

        heartbeat_stop = threading.Event()

        def maintain_lease() -> None:
            interval = max(1.0, self.lease_ttl_s / 3)
            while not heartbeat_stop.wait(interval):
                try:
                    renewed = self._acquire_dispatcher_lease("heartbeat")
                except Exception:
                    if not self._lease_valid():
                        return
                    continue
                if not self._accept_dispatcher_lease(renewed, source="heartbeat"):
                    return
                self.status.heartbeat_at = _utc_now()

        heartbeat_thread = threading.Thread(
            target=maintain_lease,
            name=f"{self.owner_id}-lease-heartbeat",
            daemon=True,
        )
        heartbeat_thread.start()
        self.status.phase = DispatcherPhase.ACTIVE
        self.status.heartbeat_at = _utc_now()
        self.status.last_cycle_started_at = self.status.heartbeat_at
        try:
            persisted_status = self.repository.get_dispatcher_status()
            self._apply_control_state(persisted_status)
            self._reap_collections()
            if self._pipeline is not None:
                reconciled, pending = self._pipeline.observe()
            else:
                self._reconcile_reservations()
                reconciled, pending = self._reconcile_attempts()
            if self._lease_lost:
                raise RuntimeError("dispatcher lease was lost during reconciliation")
            self.status.reconciled_attempts += reconciled
            self.status.pending_reconciliation = pending
            # Recovery mode keeps the lease and polls known Attempts while
            # preventing new reservations. Reopen scheduling immediately
            # after the pending set is empty, without creating duplicates.
            self._resume_after_reconciliation_if_allowed(pending)
            self.status.reconciled_attempts += self.service.reconcile_registered_manifests(
                actor_id=self.owner_id,
            )
            self._reconcile_collection_alerts()
            self.service._reclassify_unknown_scientific_failures(actor_id=self.owner_id)
            self.service._auto_retry_failed_units(actor_id=self.owner_id)
            self.service.reconcile_terminal_job_statuses(actor_id=self.owner_id)
            if self._pipeline is not None:
                assignments, prepared = self._pipeline.dispatch()
            else:
                assignments = 0
                if self._drain_requested():
                    self.status.accepting_assignments = False
                    self.status.control_mode = "drain"
                if self.status.accepting_assignments:
                    assignments += self._activate_ready_reservations()
                pending_assignments: list[Assignment] = []
                while self.status.accepting_assignments and len(pending_assignments) < self.max_assignments_per_cycle:
                    if self._drain_requested():
                        self.status.accepting_assignments = False
                        self.status.control_mode = "drain"
                        break
                    if self._lease_lost:
                        raise RuntimeError("dispatcher lease was lost before assignment")
                    assignment = self.service.schedule_once(
                        actor_id=self.owner_id,
                        ready_for_assignment=self._origin_bundle_ready,
                        should_continue=self._scan_allowed,
                    )
                    if assignment is None:
                        break
                    pending_assignments.append(assignment)
                submission_futures = [
                    self._submission_pool.submit(self._submit_assignment, assignment)
                    for assignment in pending_assignments
                ]
                for future in submission_futures:
                    future.result()
                assignments += len(pending_assignments)
                prepared = 0
                pending_reservations: list[DispatchReservation] = []
                while (
                    self.status.accepting_assignments
                    and len(pending_reservations) < self.max_assignments_per_cycle
                ):
                    reservation = self.service.prepare_dispatch_once(
                        actor_id=self.owner_id,
                        ready_for_assignment=self._origin_bundle_ready,
                        should_continue=self._scan_allowed,
                    )
                    if reservation is None:
                        break
                    pending_reservations.append(reservation)
                preparation_futures = [
                    self._preparation_pool.submit(self._prepare_reservation, reservation)
                    for reservation in pending_reservations
                ]
                for future in preparation_futures:
                    prepared += int(bool(future.result()))
            self.status.assignments += assignments
            self.status.cycle_count += 1
            renewed = self._acquire_dispatcher_lease("cycle_end")
            if not self._accept_dispatcher_lease(renewed, source="cycle_end"):
                raise RuntimeError("dispatcher lease was lost during final renewal")
            self.status.last_successful_cycle_at = _utc_now()
            self.status.last_error = None
            return True
        except Exception as exc:
            self.status.phase = DispatcherPhase.ERROR
            self.status.last_error = f"{type(exc).__name__}: {exc}"
            self.status.last_error_at = _utc_now()
            try:
                self.service._event(
                    "dispatcher.cycle_failed",
                    self.owner_id,
                    "dispatcher",
                    "dispatcher",
                    error=self.status.last_error,
                )
            except Exception:
                # The original persistence failure is already retained in
                # memory. A second failed audit write must not kill the loop.
                pass
            return False
        finally:
            heartbeat_stop.set()
            heartbeat_thread.join(timeout=2)
            # A concurrent admin drain must win over this cycle's in-memory
            # snapshot. Otherwise the old snapshot can reopen assignments at
            # the exact moment a safety control is applied.
            try:
                persisted_status = self.repository.get_dispatcher_status()
            except Exception:
                persisted_status = None
            if persisted_status is not None:
                self._apply_control_state(persisted_status)
            self._resume_after_reconciliation_if_allowed(
                self.status.pending_reconciliation,
            )
            if self._drain_requested():
                self.status.accepting_assignments = False
                self.status.control_mode = "drain"
            self.status.heartbeat_at = _utc_now()
            if not self._lease_valid():
                self.status.accepting_assignments = False
            else:
                try:
                    self.repository.put_dispatcher_status(self.status)
                except Exception:
                    # Repository writes have their own bounded retry. If the
                    # lock outlives it, the next cycle republishes status.
                    pass

    def _apply_control_state(self, persisted_status: DispatcherStatus) -> None:
        self.status.accepting_assignments = persisted_status.accepting_assignments
        self.status.control_mode = persisted_status.control_mode
        self.status.desired_state = persisted_status.desired_state
        self.status.stop_reason = persisted_status.stop_reason
        self.status.blocked_reason = persisted_status.blocked_reason
        self.status.auto_resume_allowed = persisted_status.auto_resume_allowed
        self.status.last_recovered_at = persisted_status.last_recovered_at
        self.status.collection_circuit_auto_resume_count = persisted_status.collection_circuit_auto_resume_count
        self.status.collection_circuit_auto_resume_reset_at = persisted_status.collection_circuit_auto_resume_reset_at
        self.status.collection_circuit_alert_ids = list(persisted_status.collection_circuit_alert_ids)

    def _resume_after_reconciliation_if_allowed(self, pending: int) -> None:
        if not (
            self.status.desired_state == "open"
            and self.status.auto_resume_allowed
            and self.status.blocked_reason in {
                "pending_reconciliation",
                "quarantined_reconciliation",
            }
        ):
            return
        drain_file_value = os.environ.get("RCN_DISPATCHER_DRAIN_FILE", "")
        if drain_file_value:
            Path(drain_file_value).resolve().unlink(missing_ok=True)
        self.status.accepting_assignments = True
        self.status.control_mode = "open"
        self.status.blocked_reason = (
            "quarantined_reconciliation" if pending else ""
        )

    def run_forever(self, *, interval_s: float = 1.0) -> None:
        stop_file_value = os.environ.get("RCN_DISPATCHER_STOP_FILE", "")
        stop_file = Path(stop_file_value).resolve() if stop_file_value else None
        wake_file_value = os.environ.get("RCN_DISPATCHER_WAKE_FILE", "")
        wake_file = Path(wake_file_value).resolve() if wake_file_value else None
        last_wake_marker = None
        try:
            while True:
                if stop_file is not None and stop_file.exists():
                    break
                try:
                    self.run_cycle()
                except Exception as exc:
                    self.status.phase = DispatcherPhase.ERROR
                    self.status.last_error = f"{type(exc).__name__}: {exc}"
                    self.status.last_error_at = _utc_now()
                if self._lease_lost or self.io_stop_event.is_set() or (stop_file is not None and stop_file.exists()):
                    break
                if wake_file is not None:
                    try:
                        marker = wake_file.stat().st_mtime_ns
                    except OSError:
                        marker = None
                    if marker != last_wake_marker:
                        last_wake_marker = marker
                        continue
                self._wake_event.wait(max(0.1, interval_s))
                self._wake_event.clear()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop(interrupt_io=True)

    @staticmethod
    def _drain_requested() -> bool:
        drain_file_value = os.environ.get("RCN_DISPATCHER_DRAIN_FILE", "")
        return bool(drain_file_value) and Path(drain_file_value).resolve().exists()

    def _assert_publication_lease(self) -> None:
        if not self._lease_valid():
            raise _SubmissionAborted("dispatcher lease expired before remote publication")

    def _lease_valid(self) -> bool:
        fenced = False
        with self._lease_lock:
            if self._lease_lost:
                return False
            deadline = self._lease_deadline
            wall_remaining = (self._lease_expires_at - _utc_now()).total_seconds() if self._lease_expires_at is not None else None
            checked_at = time.monotonic()
            reason = "monotonic_deadline_expired" if deadline is not None and checked_at >= deadline else (
                "wall_expiry_elapsed" if wall_remaining is not None and wall_remaining <= 0 else None)
            if reason is not None:
                self._fence_dispatcher_lease_locked()
                fenced = True
        if fenced:
            self._lease_diagnostic("lease_fenced", source="lease_valid", reason=reason,
                observed_monotonic=checked_at, previous_remaining_s=deadline - checked_at,
                previous_wall_remaining_s=wall_remaining, new_remaining_s=None,
                receipt_expires_at=self._lease_expires_at.isoformat() if self._lease_expires_at is not None else None)
        return not fenced

    def _scan_allowed(self) -> bool:
        """Check control requests inside a large queue scan, not only between cycles."""
        stop = os.environ.get("RCN_DISPATCHER_STOP_FILE", "")
        return not self._stopping and self._lease_valid() and not self.io_stop_event.is_set() and not self._drain_requested() and not (stop and Path(stop).resolve().exists())

    def stop(self, *, interrupt_io: bool = False) -> None:
        # --once joins its queued output collection. Long-lived handoff only
        # interrupts this dispatcher's local transport children, not workers.
        self._stopping = True
        self.status.accepting_assignments = False
        if interrupt_io:
            self.io_stop_event.set()
        for pool in (self._submission_pool, self._preparation_pool,
                     self._reconciliation_pool, self._collection_pool):
            pool.shutdown(wait=True, cancel_futures=interrupt_io)
        self.io_stop_event.set()
        from .schedulers.ssh import close_owned_activation_channels
        close_owned_activation_channels(self.io_stop_event)
        if not self._held_lease:
            return
        lease = self.repository.get_dispatcher_lease()
        if lease is not None and lease.owner_id == self.owner_id:
            self.status.phase = DispatcherPhase.STOPPED
            self.status.accepting_assignments = False
            self.status.control_mode = "drain"
            self.status.heartbeat_at = _utc_now()
            self.repository.put_dispatcher_status(self.status)
            self.repository.release_dispatcher_lease(self.owner_id)
        self._held_lease = False

    def _submit_assignment(self, assignment: Assignment) -> bool:
        if self.io_stop_event.is_set() or self._lease_lost:
            return False
        job = self.repository.get_job(assignment.job_id)
        if job is None:
            raise KeyError(f"job not found after assignment: {assignment.job_id}")
        unit = next(item for item in job.work_units if item.work_unit_id == assignment.work_unit_id)
        attempt = next(
            (item for item in unit.attempts if item.attempt_id == assignment.attempt_id),
            None,
        )
        if attempt is None:
            return True  # A released assignment must not submit its successor.
        if not _attempt_observation_is_current(unit, attempt):
            return True

        # The origin gate runs before scheduling, but the bundle can be
        # replaced between that check and adapter submission.  Recheck the
        # exact assignment-bound runtime here so a stale bundle cannot consume
        # an Attempt or reach a worker that will reject it.
        if not self._origin_bundle_matches_assignment(job, unit, assignment):
            self._release_unsubmitted_assignment(
                job.job_id,
                unit.work_unit_id,
                assignment.attempt_id or "",
            )
            return False

        # Persist the fixed SSH identity before publishing anything. After a
        # crash, recovery polls this same identity instead of resubmitting.
        try:
            adapter = self.adapter_provider(assignment.machine_id)
        except Exception as exc:
            self._release_unsubmitted_assignment(
                job.job_id, unit.work_unit_id, attempt.attempt_id,
                reason=safe_failure_reason(exc, action="submission adapter unavailable"),
            )
            return False
        identity_builder = getattr(adapter, "external_id", None)
        intended_external = identity_builder(job, assignment) if callable(identity_builder) else None

        def mark_submitting(current: JobEnvelope) -> None:
            current_unit = next(item for item in current.work_units if item.work_unit_id == unit.work_unit_id)
            current_attempt = next(item for item in current_unit.attempts if item.attempt_id == attempt.attempt_id)
            if _cancellation_won(current, current_unit, current_attempt):
                raise _SubmissionAborted
            if current_attempt.state not in {"assigned", "submitting"}:
                raise _SubmissionAborted
            if current_attempt.external_run_id and current_attempt.external_run_id != intended_external:
                raise _SubmissionAborted
            current_attempt.state = "submitting"
            if intended_external:
                current_attempt.external_run_id = intended_external

        try:
            self.repository.mutate_job(job.job_id, mark_submitting, hydrate_blobs=False)
        except _SubmissionAborted:
            return True
        try:
            self._assert_publication_lease()
            external_run_id = adapter.submit(job, assignment)
            if intended_external and external_run_id != intended_external:
                raise SubmissionUncertainError("adapter changed the fixed execution identity",
                                               external_run_id=intended_external)
        except SubmissionUncertainError as exc:
            self._retain_uncertain_submission(job.job_id, unit.work_unit_id, attempt.attempt_id,
                intended_external or exc.external_run_id, safe_failure_reason(exc, action="submission"))
            return False
        except PreLaunchSubmissionError as exc:
            reason = f"remote launch deferred before activation: {exc}"
            self._release_unsubmitted_assignment(
                job.job_id,
                unit.work_unit_id,
                assignment.attempt_id or "",
                reason=reason,
                event_type="attempt.prelaunch_deferred",
                proven_external_id=intended_external,
                evidence={
                    "reason_code": exc.reason_code,
                    "error_type": exc.error_type,
                    "timeout_s": exc.timeout_s,
                },
            )
            return False
        except Exception as exc:
            if intended_external:
                self._retain_uncertain_submission(job.job_id, unit.work_unit_id, attempt.attempt_id,
                    intended_external, safe_failure_reason(exc, action="submission acknowledgement"))
                return False
            self._fail_observed_attempt(
                job.job_id, unit.work_unit_id, attempt.attempt_id,
                error=safe_failure_reason(exc, action="dispatcher submit"),
                failure_class=classify_submission_failure(exc),
            )
            return False

        cancel_after_submit = False

        def record_external(current: JobEnvelope) -> None:
            nonlocal cancel_after_submit
            current_unit = next(item for item in current.work_units if item.work_unit_id == unit.work_unit_id)
            current_attempt = next(
                item for item in current_unit.attempts if item.attempt_id == attempt.attempt_id
            )
            if not _attempt_observation_is_current(current_unit, current_attempt):
                return
            # Cancellation may win while the adapter stages the bundle. Keep
            # that intent and cancel the now-known remote run instead of
            # reviving the aggregate as running.
            if current_unit.status == WorkUnitStatus.CANCELLED or current_attempt.state in {"cancelled", "cancel_pending"}:
                current_attempt.external_run_id = external_run_id
                current_attempt.state = "cancel_pending"
                current_attempt.finished_at = None
                current_attempt.last_observed_at = _utc_now()
                cancel_after_submit = True
                return
            current_attempt.external_run_id = external_run_id
            current_attempt.remote_run_allocated = True
            current_attempt.prepared = bool(assignment.prepared)
            # Submission only stages the remote bundle.  The worker may still
            # be waiting for its own slot, so activity starts only after a
            # poll explicitly reports RUNNING.
            current_attempt.state = "assigned"
            now = _utc_now()
            current_attempt.assigned_at = current_attempt.assigned_at or now
            current_attempt.last_observed_at = now
            current_unit.status = WorkUnitStatus.ASSIGNED
            current_unit.dispatch_failure_count = 0
            current_unit.dispatch_not_before_at = None
            current_unit.failure_reason = None
            current.status = JobStatus.RUNNING

        self.repository.mutate_job(job.job_id, record_external, hydrate_blobs=False)
        if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt.attempt_id):
            return True
        if cancel_after_submit:
            try:
                adapter.cancel(external_run_id)
            except Exception as exc:
                self.service._event(
                    "attempt.cancel_pending",
                    self.owner_id,
                    "attempt",
                    attempt.attempt_id,
                    job_id=job.job_id,
                    work_unit_id=unit.work_unit_id,
                    reason=f"cancel after submit failed: {exc}",
                )
        else:
            # ``record_external`` mutates a freshly loaded aggregate. Keep
            # this cycle's snapshot aligned so the immediate poll addresses
            # the actual remote run instead of the pre-submit empty ID.
            attempt.external_run_id = external_run_id
            attempt.remote_run_allocated = True
            attempt.prepared = bool(assignment.prepared)
            attempt.state = "assigned"
            attempt.assigned_at = attempt.assigned_at or _utc_now()
        self.service._event(
            "attempt.submitted",
            self.owner_id,
            "attempt",
            attempt.attempt_id,
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
            machine_id=assignment.machine_id,
            external_run_id=external_run_id,
        )
        # Confirm the remote lifecycle immediately when possible.  A queued
        # response remains assigned; transient observation failures are
        # deferred to the next reconcile cycle without burning a retry.
        if not cancel_after_submit:
            self._poll_attempt(job, unit, attempt.attempt_id, allow_uncertain=False)
        return True

    def _retain_uncertain_submission(self, job_id, unit_id, attempt_id, external_id, reason):
        retained = False
        def retain(current):
            nonlocal retained
            retained = False
            unit = next(u for u in current.work_units if u.work_unit_id == unit_id)
            attempt = next(a for a in unit.attempts if a.attempt_id == attempt_id)
            if not _attempt_observation_is_current(unit, attempt):
                return
            retained = True
            if attempt.external_run_id and attempt.external_run_id != external_id:
                raise RuntimeError("uncertain publication identity mismatch")
            attempt.external_run_id = external_id
            if _cancellation_won(current, unit, attempt):
                attempt.state = "cancel_pending"
                attempt.finished_at = None
                return
            attempt.state = "reconcile_pending"
            attempt.failure_reason = "submission delivery unknown: " + reason
            unit.status = WorkUnitStatus.RECONCILE_PENDING
            unit.failure_reason = attempt.failure_reason
            current.status = JobStatus.RUNNING
        self.repository.mutate_job(job_id, retain, hydrate_blobs=False)
        if not retained:
            return
        self.service._event("attempt.submission_delivery_unknown", self.owner_id, "attempt", attempt_id,
            job_id=job_id, work_unit_id=unit_id, external_run_id=external_id,
            reason=reason, retry_budget_preserved=True)

    def _expected_origin_runtime(self, job: JobEnvelope, unit: WorkUnit) -> str | None:
        """Return the current approval-bound runtime for an origin bundle."""
        if self.origin_spool is None:
            return None
        approval_id = unit.solver_approval_id or job.solver_approval_id
        if approval_id:
            approval = self.repository.get_solver_approval(approval_id)
            if approval is not None and approval.runtime_version:
                return approval.runtime_version
        latest = unit.attempts[-1] if unit.attempts else None
        return latest.runtime_version if latest is not None else None

    def _reseal_queued_origin_bundle(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        expected_runtime: str | None,
    ):
        """Rebind only an unstarted Unit's validated origin envelope."""
        if self.origin_spool is None:
            return None
        status = self.origin_spool.status(job, unit)
        if (
            not status.ready
            or not expected_runtime
            or status.runtime_version == expected_runtime
        ):
            return status
        active_states = {
            "assigned",
            "submitting",
            "running",
            "cancel_pending",
            "reconcile_pending",
            "uncertain",
            "collecting",
        }
        if unit.status != WorkUnitStatus.QUEUED or any(
            attempt.state in active_states for attempt in unit.attempts
        ):
            return status
        result = self.origin_spool.reseal_runtime(job, unit, expected_runtime)
        self.service._event(
            "origin_bundle.runtime_resealed",
            self.owner_id,
            "work_unit",
            unit.work_unit_id,
            job_id=job.job_id,
            previous_runtime_version=result["previous_runtime_version"],
            runtime_version=result["runtime_version"],
            previous_sha256=result["previous_sha256"],
            sha256=result["sha256"],
            retained_path=result["retained_path"],
        )
        return self.origin_spool.status(job, unit)

    def _report_origin_bundle_wait(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        reason: str,
    ) -> None:
        key = (job.job_id, unit.work_unit_id, reason)
        if key in self._reported_unready_bundles:
            return
        self._reported_unready_bundles.add(key)
        self.service._event(
            "origin_bundle.waiting",
            self.owner_id,
            "work_unit",
            unit.work_unit_id,
            job_id=job.job_id,
            reason=reason,
        )

    def _prepare_reservation(self, reservation: DispatchReservation) -> bool:
        if self.io_stop_event.is_set() or self._lease_lost:
            return False
        job = self.repository.get_job(reservation.job_id)
        if job is None:
            self.service.finish_dispatch_reservation(
                reservation.reservation_id,
                state="cancelled",
                reason="job disappeared before standby preparation",
                actor_id=self.owner_id,
            )
            return False
        if reservation.job_request_hash is not None and reservation.job_request_hash != job.request_hash:
            # Retain the original external identity if publication may already
            # have happened; reconciliation retires only an acknowledged run.
            reservation.expires_at = _utc_now()
            reservation.reason = "Job request changed before standby preparation"
            self.repository.put_dispatch_reservation(reservation, expected_state="preparing")
            return False
        unit = next(
            (
                item
                for item in job.work_units
                if item.work_unit_id == reservation.work_unit_id
            ),
            None,
        )
        if unit is None or unit.status != WorkUnitStatus.QUEUED:
            self.service.finish_dispatch_reservation(
                reservation.reservation_id,
                state="cancelled",
                reason="unit disappeared or left queued state before standby preparation",
                actor_id=self.owner_id,
            )
            return False
        assignment = Assignment(
            job_id=reservation.job_id,
            work_unit_id=reservation.work_unit_id,
            machine_id=reservation.machine_id,
            scheduler="pilot-standby-prepare",
            attempt_id=reservation.reservation_id,
            solver_variant=reservation.solver_variant,
            solver_approval_id=reservation.solver_approval_id,
            solver_compatibility_fingerprint=reservation.solver_compatibility_fingerprint,
            runtime_version=reservation.runtime_version,
            dispatch_reservation_id=reservation.reservation_id,
            prepared=True,
            external_run_id=reservation.external_run_id,
        )
        if not self._origin_bundle_matches_assignment(job, unit, assignment):
            self.service.finish_dispatch_reservation(
                reservation.reservation_id,
                state="cancelled",
                reason="standby blocked until origin bundle runtime matches approval",
                actor_id=self.owner_id,
            )
            return False
        publication_invoked = False
        try:
            # A standby has no Attempt yet: bundle builders fall back to the
            # Unit's resolved resources. Bind that fallback to the reservation
            # in a private copy, preserving the submitted Unit identity and DB.
            prepared_job = job.model_copy(deep=True)
            prepared_unit = next(
                item for item in prepared_job.work_units
                if item.work_unit_id == reservation.work_unit_id
            )
            if any(item.attempt_id == assignment.attempt_id for item in prepared_unit.attempts):
                raise ValueError("standby reservation identity conflicts with an existing Attempt")
            if reservation.resolved_resources is not None:
                prepared_unit.resolved_resources = reservation.resolved_resources.model_copy(deep=True)
            adapter = self.adapter_provider(reservation.machine_id)
            publication_invoked = True
            prepare_with_receipt = getattr(adapter, "prepare_with_receipt", None)
            if callable(prepare_with_receipt):
                def before_publication(request):
                    self._assert_publication_lease()
                    return self.service.bind_dispatch_reservation_request(
                        reservation.reservation_id, job_request_hash=prepared_job.request_hash,
                        request=request, actor_id=self.owner_id,
                    )
                external = prepare_with_receipt(
                    prepared_job, assignment, reservation.external_run_id or "",
                    before_publication=before_publication,
                )
            else:
                self._assert_publication_lease()
                external = adapter.prepare(prepared_job, assignment, reservation.external_run_id or "")
            if external != reservation.external_run_id:
                raise RuntimeError("prepared scheduler changed the sealed external run identity")
            self.service.mark_dispatch_reservation_prepared(
                reservation.reservation_id,
                actor_id=self.owner_id,
            )
            return True
        except PreLaunchSubmissionError as exc:
            reason = f"standby preparation failed: {exc}"
            self.service.finish_dispatch_reservation(
                reservation.reservation_id,
                state="cancelled",
                reason=reason,
                actor_id=self.owner_id,
            )
            self.service.defer_dispatch(
                reservation.job_id,
                reservation.work_unit_id,
                reason=reason,
                actor_id=self.owner_id,
            )
            return False
        except Exception as exc:
            if not publication_invoked:
                self.service.finish_dispatch_reservation(reservation.reservation_id, state="cancelled",
                    reason=safe_failure_reason(exc, action="standby before publication"), actor_id=self.owner_id)
                return False
            # Publication or a following local persistence operation may have
            # succeeded. Retain the reservation and its external identity.
            self.service._event("reservation.submission_delivery_unknown", self.owner_id,
                "reservation", reservation.reservation_id,
                external_run_id=reservation.external_run_id,
                reason=safe_failure_reason(exc, action="standby publication"))
            return False

    def _activate_ready_reservations(self, machine_id: str | None = None) -> int:
        pending: list[tuple[DispatchReservation, Assignment]] = []
        for reservation in self.repository.list_dispatch_reservations(
            active_only=True,
            machine_id=machine_id,
        ):
            if reservation.state != "prepared":
                continue
            assignment = self.service.activate_dispatch_reservation(
                reservation.reservation_id,
                actor_id=self.owner_id,
                ready_for_assignment=self._origin_bundle_ready,
            )
            if assignment is None:
                continue
            pending.append((reservation, assignment))
        futures = [
            self._submission_pool.submit(self._activate_prepared_reservation, reservation, assignment)
            for reservation, assignment in pending
        ]
        return sum(int(bool(future.result())) for future in futures)

    def _activate_prepared_reservation(
        self,
        reservation: DispatchReservation,
        assignment: Assignment,
    ) -> bool:
        if self.io_stop_event.is_set() or self._lease_lost:
            return False
        current = self.repository.get_operational_job(assignment.job_id)
        current_unit = (
            next(
                (item for item in current.work_units if item.work_unit_id == assignment.work_unit_id),
                None,
            )
            if current is not None
            else None
        )
        current_attempt = (
            next(
                (item for item in current_unit.attempts if item.attempt_id == assignment.attempt_id),
                None,
            )
            if current_unit is not None
            else None
        )
        if (
            current is None
            or current_unit is None
            or current_attempt is None
            or _cancellation_won(current, current_unit, current_attempt)
        ):
            return False
        try:
            adapter = self.adapter_provider(assignment.machine_id)
            self._assert_publication_lease()
            adapter.activate(
                assignment.external_run_id or ""
            )
        except Exception as exc:
            if not self._attempt_is_current(
                assignment.job_id, assignment.work_unit_id, assignment.attempt_id or "",
            ):
                return True
            self._mark_uncertain(
                assignment.job_id,
                assignment.work_unit_id,
                assignment.attempt_id or "",
                safe_failure_reason(exc, action="standby activation"),
            )
            return False
        if not self._mark_prepared_activated(assignment):
            try:
                adapter.cancel(assignment.external_run_id or "")
            except Exception as exc:
                self._mark_cancel_pending(
                    assignment.job_id,
                    assignment.work_unit_id,
                    assignment.attempt_id or "",
                    safe_failure_reason(exc, action="cancel after standby activation"),
                )
            self.service.finish_dispatch_reservation(
                reservation.reservation_id,
                state="cancelled",
                reason="cancellation won while standby activation was in flight",
                actor_id=self.owner_id,
            )
            return True
        self.service.finish_dispatch_reservation(
            reservation.reservation_id,
            state="consumed",
            reason="standby activated after a slot became available",
            actor_id=self.owner_id,
        )
        self.service._event(
            "attempt.submitted",
            self.owner_id,
            "attempt",
            assignment.attempt_id or "",
            job_id=assignment.job_id,
            work_unit_id=assignment.work_unit_id,
            machine_id=assignment.machine_id,
            external_run_id=assignment.external_run_id,
            dispatch_reservation_id=reservation.reservation_id,
        )
        job = self.repository.get_job(assignment.job_id)
        unit = (
            next(
                (item for item in job.work_units if item.work_unit_id == assignment.work_unit_id),
                None,
            )
            if job is not None
            else None
        )
        if job is not None and unit is not None and assignment.attempt_id:
            self._poll_attempt(job, unit, assignment.attempt_id, allow_uncertain=False)
        return True

    @staticmethod
    def _reservation_observation_matches(
        reservation: DispatchReservation, remote: RemoteRunRecord, job: JobEnvelope | None,
    ) -> bool:
        # Legacy generic adapters used the Job hash directly. Real SSH bundle
        # hashes are different; missing frozen evidence never licenses a guess.
        expected_hash = reservation.request_hash
        if expected_hash is None and job is not None:
            if reservation.job_request_hash not in {None, job.request_hash}:
                return False
            expected_hash = job.request_hash
        return bool(
            expected_hash is not None
            and remote.external_run_id == reservation.external_run_id
            and remote.machine_id == reservation.machine_id
            and remote.job_id == reservation.job_id
            and remote.work_unit_id == reservation.work_unit_id
            and remote.request_hash == expected_hash
        )

    @staticmethod
    def _reservation_cancelled_before_launch(
        reservation: DispatchReservation, remote: RemoteRunRecord, unit: WorkUnit | None,
    ) -> bool:
        return bool(
            remote.state == RemoteRunState.CANCELLED
            and remote.message.startswith("cancelled before launch")
            and not remote.artifacts_available
            and not (unit is not None and any(
                (attempt.dispatch_reservation_id == reservation.reservation_id
                 or attempt.external_run_id == reservation.external_run_id)
                and (attempt.execution_started or attempt.execution_completed or attempt.collected_at
                     or attempt.state in {"running", "collecting", "completed"})
                for attempt in unit.attempts
            ))
        )

    def _reconcile_reservations(self, machine_id: str | None = None) -> None:
        now = _utc_now()
        draining = self._drain_requested() or not self.status.accepting_assignments
        for reservation in self.repository.list_dispatch_reservations(active_only=True, machine_id=machine_id):
            if self.io_stop_event.is_set() or self._lease_lost:
                return
            job = self.repository.get_job(reservation.job_id)
            unit = (
                next(
                    (
                        item for item in job.work_units
                        if item.work_unit_id == reservation.work_unit_id
                    ),
                    None,
                )
                if job is not None
                else None
            )
            request_changed = bool(job is not None and reservation.job_request_hash is not None
                                   and reservation.job_request_hash != job.request_hash)
            if (reservation.state == "preparing" and not draining and not request_changed
                    and reservation.expires_at > now and unit is not None
                    and unit.status == WorkUnitStatus.QUEUED):
                try:
                    run = self.adapter_provider(reservation.machine_id).poll(reservation.external_run_id or "")
                    if (self._reservation_observation_matches(reservation, run, job)
                            and run.state in {RemoteRunState.PREPARED, RemoteRunState.STAGED, RemoteRunState.QUEUED}):
                        self.service.mark_dispatch_reservation_prepared(reservation.reservation_id, actor_id=self.owner_id)
                    elif (self._reservation_observation_matches(reservation, run, job)
                          and self._reservation_cancelled_before_launch(reservation, run, unit)):
                        self.service.finish_dispatch_reservation(
                            reservation.reservation_id, state="cancelled", actor_id=self.owner_id,
                            reason="original standby cancelled before launch",
                            expected_state="preparing",
                        )
                except Exception:
                    pass  # Unknown delivery retains this reservation, never another ID.
                continue
            if reservation.state == "activating" and unit is not None and unit.attempts:
                attempt = unit.attempts[-1]
                if (
                    not _attempt_observation_is_current(unit, attempt)
                    or (attempt.dispatch_reservation_id is not None
                        and attempt.dispatch_reservation_id != reservation.reservation_id)
                    or attempt.external_run_id != reservation.external_run_id
                ):
                    continue  # An old standby must not activate a successor attempt.
                if _cancellation_won(job, unit, attempt):
                    try:
                        self.adapter_provider(reservation.machine_id).cancel(
                            reservation.external_run_id or ""
                        )
                    except Exception as exc:
                        self._mark_cancel_pending(
                            job.job_id,
                            unit.work_unit_id,
                            attempt.attempt_id,
                            safe_failure_reason(exc, action="cancel recovered standby activation"),
                        )
                        continue
                    self.service.finish_dispatch_reservation(
                        reservation.reservation_id,
                        state="cancelled",
                        reason="cancelled Job invalidated activating standby",
                        actor_id=self.owner_id,
                    )
                    continue
                config = self.repository.get_machine_execution_config(reservation.machine_id)
                if draining or (config is not None and (not config.enabled or not self.service.runtime_policy.accepts_worker_runtime(config.runtime_version))):
                    continue  # Preserve its existing identity for later eligible recovery.
                try:
                    self._assert_publication_lease()
                    self.adapter_provider(reservation.machine_id).activate(
                        reservation.external_run_id or ""
                    )
                except Exception:
                    continue
                recovered_assignment = Assignment(
                    job_id=reservation.job_id,
                    work_unit_id=reservation.work_unit_id,
                    machine_id=reservation.machine_id,
                    scheduler="pilot-standby-recovery",
                    attempt_id=unit.attempts[-1].attempt_id,
                    external_run_id=reservation.external_run_id,
                    prepared=True,
                    solver_variant=attempt.solver_variant,
                    solver_approval_id=attempt.solver_approval_id,
                    solver_compatibility_fingerprint=attempt.solver_compatibility_fingerprint,
                    runtime_version=attempt.runtime_version,
                    dispatch_reservation_id=attempt.dispatch_reservation_id,
                )
                if not self._mark_prepared_activated(recovered_assignment):
                    try:
                        self.adapter_provider(reservation.machine_id).cancel(
                            reservation.external_run_id or ""
                        )
                    except Exception as exc:
                        self._mark_cancel_pending(
                            job.job_id,
                            unit.work_unit_id,
                            attempt.attempt_id,
                            safe_failure_reason(exc, action="cancel raced standby recovery"),
                        )
                        continue
                    self.service.finish_dispatch_reservation(
                        reservation.reservation_id,
                        state="cancelled",
                        reason="cancellation won while standby recovery was in flight",
                        actor_id=self.owner_id,
                    )
                    continue
                self._poll_attempt(job, unit, recovered_assignment.attempt_id, allow_uncertain=False)
                self.service.finish_dispatch_reservation(
                    reservation.reservation_id,
                    state="consumed",
                    reason="activation recovered after Dispatcher restart",
                    actor_id=self.owner_id,
                )
                continue
            if (draining or request_changed or reservation.expires_at <= now
                    or unit is None or unit.status != WorkUnitStatus.QUEUED):
                try:
                    adapter = self.adapter_provider(reservation.machine_id)
                    external_id = reservation.external_run_id or ""
                    if not external_id:
                        continue
                    remote = adapter.poll(external_id)
                    if not self._reservation_observation_matches(reservation, remote, job):
                        continue
                    if remote.state in {RemoteRunState.PREPARED, RemoteRunState.STAGED, RemoteRunState.QUEUED}:
                        adapter.cancel(external_id)
                        remote = adapter.poll(external_id)
                    if (not self._reservation_observation_matches(reservation, remote, job)
                            or not self._reservation_cancelled_before_launch(reservation, remote, unit)):
                        # cancel() only posts a signal. Unknown/nonterminal or
                        # unexpected executed results retain the original slot
                        # and identity for reconciliation, never another run.
                        continue
                except Exception:
                    continue  # Do not release an uncertain remote reservation.
                self.service.finish_dispatch_reservation(
                    reservation.reservation_id,
                    state=("expired" if reservation.expires_at <= now else "cancelled"),
                    reason=(
                        "standby reservation expired"
                        if reservation.expires_at <= now
                        else "standby invalidated by drain or aggregate change"
                    ),
                    actor_id=self.owner_id,
                    expected_state=reservation.state,
                )

    def _mark_prepared_activated(self, assignment: Assignment) -> bool:
        activated = False

        def apply(current: JobEnvelope) -> None:
            nonlocal activated
            activated = False
            unit = next(
                item for item in current.work_units
                if item.work_unit_id == assignment.work_unit_id
            )
            attempt = next(
                item for item in unit.attempts
                if item.attempt_id == assignment.attempt_id
            )
            if _cancellation_won(current, unit, attempt):
                return
            attempt.state = "assigned"
            attempt.last_observed_at = _utc_now()
            attempt.external_run_id = assignment.external_run_id
            attempt.prepared = True
            attempt.remote_run_allocated = bool(assignment.external_run_id)
            unit.status = WorkUnitStatus.ASSIGNED
            current.status = JobStatus.RUNNING
            activated = True

        self.repository.mutate_job(assignment.job_id, apply, hydrate_blobs=False)
        return activated

    def _origin_bundle_ready(self, job: JobEnvelope, unit: WorkUnit) -> bool:
        """Keep a unit queued until its origin has atomically published it."""
        if job.execution_profile_id == "rcn-safe-fake-v1":
            return True
        if self.origin_spool is None:
            return True
        try:
            expected_runtime = self._expected_origin_runtime(job, unit)
            status = self._reseal_queued_origin_bundle(job, unit, expected_runtime)
            assert status is not None
            if status.ready:
                if not self.service.runtime_policy.accepts_worker_runtime(status.runtime_version):
                    reason = (
                        "sealed origin bundle runtime is not accepted: "
                        f"{status.runtime_version or 'unknown'}; expected {self.status.runtime_version}"
                    )
                elif expected_runtime and status.runtime_version != expected_runtime:
                    reason = (
                        "sealed origin bundle runtime mismatch: "
                        f"bundle={status.runtime_version}; expected assignment runtime={expected_runtime}"
                    )
                else:
                    self._reported_unready_bundles = {
                        key for key in self._reported_unready_bundles
                        if key[:2] != (job.job_id, unit.work_unit_id)
                    }
                    return True
            else:
                reason = "sealed origin bundle has not been published"
        except Exception as exc:
            reason = f"origin bundle validation pending: {type(exc).__name__}: {exc}"

        self._report_origin_bundle_wait(job, unit, reason)
        return False

    def _origin_bundle_matches_assignment(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        assignment: Assignment,
    ) -> bool:
        if job.execution_profile_id == "rcn-safe-fake-v1":
            return True
        if self.origin_spool is None:
            return True
        try:
            status = self.origin_spool.status(job, unit)
            expected_runtime = assignment.runtime_version or self._expected_origin_runtime(job, unit)
            if status.ready and expected_runtime and status.runtime_version != expected_runtime:
                status = self._reseal_unpublished_assignment(job, unit, assignment, status)
            if not status.ready:
                reason = "sealed origin bundle has not been published"
            elif not self.service.runtime_policy.accepts_worker_runtime(status.runtime_version):
                reason = (
                    "sealed origin bundle runtime is not accepted: "
                    f"{status.runtime_version or 'unknown'}"
                )
            elif expected_runtime and status.runtime_version != expected_runtime:
                reason = (
                    "sealed origin bundle runtime mismatch: "
                    f"bundle={status.runtime_version}; expected assignment runtime={expected_runtime}"
                )
            else:
                return True
        except Exception as exc:
            reason = f"origin bundle validation pending: {type(exc).__name__}: {exc}"
        self._report_origin_bundle_wait(job, unit, reason)
        self.service._event(
            "origin_bundle.runtime_mismatch" if "runtime" in reason else "origin_bundle.validation_deferred",
            self.owner_id,
            "work_unit",
            unit.work_unit_id,
            job_id=job.job_id,
            attempt_id=assignment.attempt_id,
            reason=reason,
        )
        return False

    def _reseal_unpublished_assignment(self, job, unit, assignment, status):
        """Rebind an explicitly equivalent runtime before remote publication."""
        from .runtime_compatibility import is_registered_runtime_successor
        original = self.service._resolve_unit_approval(job, unit)
        execution = self.repository.get_solver_approval(assignment.solver_approval_id or "")
        if (original is None or execution is None
                or not is_registered_runtime_successor(original, execution)
                or execution.runtime_version != assignment.runtime_version
                or execution.fingerprint != assignment.solver_compatibility_fingerprint
                or not self.service.runtime_policy.accepts_new_approval(execution.runtime_version)):
            return status
        # Re-read the persisted identity. The job passed to a submission pool
        # can be older than an uncertain publication or a competing activation.
        current = self.repository.get_job(job.job_id)
        current_unit = next((item for item in current.work_units if item.work_unit_id == unit.work_unit_id), None) if current else None
        if current is None or current_unit is None or current.request_hash != job.request_hash:
            return status
        if assignment.dispatch_reservation_id:
            reservation = self.repository.get_dispatch_reservation(assignment.dispatch_reservation_id)
            if (reservation is None or reservation.state != "preparing" or reservation.request_hash is not None
                    or reservation.external_run_id != assignment.external_run_id
                    or current_unit.status != WorkUnitStatus.QUEUED
                    or any(attempt.state in {"assigned", "submitting", "running", "uncertain", "reconcile_pending",
                                             "cancel_pending", "collecting"} for attempt in current_unit.attempts)):
                return status
        else:
            attempt = next((item for item in current_unit.attempts if item.attempt_id == assignment.attempt_id), None)
            if (attempt is None or current_unit.status != WorkUnitStatus.ASSIGNED or attempt.state != "assigned"
                    or attempt.external_run_id or attempt.remote_run_allocated or attempt.execution_started
                    or attempt.execution_completed or attempt.prepared or attempt.dispatch_reservation_id
                    or _cancellation_won(current, current_unit, attempt)
                    or attempt.runtime_version != execution.runtime_version
                    or attempt.solver_approval_id != execution.approval_id):
                return status
        result = self.origin_spool.reseal_runtime(current, current_unit, execution.runtime_version)
        self.service._event("origin_bundle.execution_runtime_resealed", self.owner_id, "work_unit", unit.work_unit_id,
            job_id=job.job_id, attempt_id=assignment.attempt_id, dispatch_reservation_id=assignment.dispatch_reservation_id,
            approval_id=execution.approval_id, predecessor_approval_id=original.approval_id,
            equivalence_sha256=execution.runtime_equivalence_sha256, **result)
        return self.origin_spool.status(current, current_unit)

    @atomic_metadata
    def _release_unsubmitted_assignment(
        self,
        job_id: str,
        work_unit_id: str,
        attempt_id: str,
        *,
        reason: str = "waiting for a matching sealed origin bundle",
        event_type: str = "origin_bundle.assignment_released",
        evidence: dict[str, object] | None = None,
        proven_external_id: str | None = None,
    ) -> None:
        """Return a proven pre-launch assignment without burning a retry."""
        released = False
        def apply(current: JobEnvelope) -> None:
            nonlocal released
            released = False
            unit = next(item for item in current.work_units if item.work_unit_id == work_unit_id)
            if unit.status != WorkUnitStatus.ASSIGNED or not unit.attempts:
                return
            attempt = unit.attempts[-1]
            if attempt.attempt_id != attempt_id:
                return
            if attempt.external_run_id and attempt.external_run_id != proven_external_id:
                return
            if attempt.execution_started or attempt.execution_completed:
                return
            # Preserve the immutable ledger identity even though this does not
            # consume a scientific retry. A later assignment gets a fresh ID.
            attempt.state = "cancelled"
            attempt.finished_at = _utc_now()
            attempt.failure_class = FailureClass.INFRASTRUCTURE
            attempt.failure_reason = reason
            self.service._compute_credits.settle_attempt(
                current, unit, attempt, outcome="infrastructure", actual_duration_s=0,
                actor_id=self.owner_id,
            )
            released = True
            unit.attempt_count = max(0, unit.attempt_count - 1)
            unit.status = WorkUnitStatus.QUEUED
            unit.assigned_machine_id = None
            unit.failure_reason = reason
            unit.dispatch_failure_count += 1
            backoff_s = min(300, 15 * (2 ** min(unit.dispatch_failure_count - 1, 5)))
            unit.dispatch_not_before_at = _utc_now() + timedelta(seconds=backoff_s)
            if not any(candidate.status in {WorkUnitStatus.ASSIGNED, WorkUnitStatus.RUNNING,
                                            WorkUnitStatus.RECONCILE_PENDING, WorkUnitStatus.COLLECTING}
                       for candidate in current.work_units):
                current.status = JobStatus.QUEUED

        self.repository.mutate_job(job_id, apply, hydrate_blobs=False, atomic_callback=True)
        if not released:
            return
        self.service._event(
            event_type,
            self.owner_id,
            "work_unit",
            work_unit_id,
            job_id=job_id,
            attempt_id=attempt_id,
            reason=reason,
            retry_budget_preserved=True,
            **(evidence or {}),
        )

    def _pending_reconciliation_work(self):
        work_by_machine: dict[str, list[tuple[JobEnvelope, WorkUnit, str, str]]] = {}
        for job in self.repository.list_operational_jobs(statuses={
            JobStatus.QUEUED,
            JobStatus.RUNNING,
            JobStatus.FAILED_RETRIABLE,
            JobStatus.FAILED_TERMINAL,
            JobStatus.CANCELLED,
        }):
            for unit in job.work_units:
                for attempt in unit.attempts:
                    if not _attempt_observation_is_current(unit, attempt):
                        continue
                    if self._is_uncertain_remote_recovery(unit, attempt):
                        work_by_machine.setdefault(attempt.machine_id or "", []).append(
                            (job, unit, attempt.attempt_id, "recover_uncertain")
                        )
                        continue
                    if attempt.state not in {
                        "assigned",
                        "submitting",
                        "running",
                        "cancel_pending",
                        "reconcile_pending",
                        "uncertain",
                        "collecting",
                    }:
                        continue
                    if not attempt.machine_id:
                        continue
                    if attempt.state in {"assigned", "submitting"} and attempt.external_run_id:
                        action = "poll"
                    elif attempt.state in {"assigned", "submitting"}:
                        action = "submit"
                    elif not attempt.external_run_id:
                        continue
                    else:
                        action = "cancel" if attempt.state == "cancel_pending" else "poll"
                    work_by_machine.setdefault(attempt.machine_id, []).append(
                        (job, unit, attempt.attempt_id, action)
                    )

        return work_by_machine

    def _reconcile_attempts(self) -> tuple[int, int]:
        work_by_machine = self._pending_reconciliation_work()
        # One-shot recovery intentionally joins its observations before it
        # reports a result. Long-lived production uses DispatchPipeline instead
        # and never waits on this all-machines barrier.
        futures = [
            self._reconciliation_pool.submit(self._reconcile_machine_attempts, work)
            for work in work_by_machine.values()
        ]
        reconciled = 0
        pending = 0
        for future in futures:
            machine_reconciled, machine_pending = future.result()
            reconciled += machine_reconciled
            pending += machine_pending
        return reconciled, pending

    def _reconcile_machine_attempts(
        self,
        work: list[tuple[JobEnvelope, WorkUnit, str, str]],
    ) -> tuple[int, int]:
        reconciled = 0
        pending = 0
        for job, unit, attempt_id, action in work:
            self._repair_execution_boundary_evidence(job, unit, attempt_id)
            if action == "recover_uncertain":
                handled = self._recover_uncertain_attempt(job, unit, attempt_id)
            elif action == "submit":
                attempt = next(item for item in unit.attempts if item.attempt_id == attempt_id)
                self._submit_assignment(Assignment(
                    job_id=job.job_id,
                    work_unit_id=unit.work_unit_id,
                    machine_id=attempt.machine_id or "",
                    scheduler="dispatcher-recovery",
                    attempt_id=attempt_id,
                    solver_variant=attempt.solver_variant,
                    solver_approval_id=attempt.solver_approval_id,
                    solver_compatibility_fingerprint=attempt.solver_compatibility_fingerprint,
                    runtime_version=attempt.runtime_version,
                    dispatch_reservation_id=attempt.dispatch_reservation_id,
                    prepared=attempt.prepared,
                    external_run_id=attempt.external_run_id,
                ))
                # Submission failure paths either release the pre-launch
                # assignment or persist a classified Unit failure. Both are
                # reconciled outcomes, not uncertain remote observations.
                handled = True
            elif action == "cancel":
                handled = self._cancel_attempt(job, unit, attempt_id)
            else:
                handled = self._poll_attempt(job, unit, attempt_id)
            if handled:
                reconciled += 1
            else:
                pending += 1
        return reconciled, pending

    def _repair_execution_boundary_evidence(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        attempt_id: str,
    ) -> None:
        """Backfill boundary facts that are provable from persisted reservation state."""

        attempt = next(item for item in unit.attempts if item.attempt_id == attempt_id)
        fields: list[str] = []
        remote = self.repository.get_remote_run(attempt.external_run_id) if attempt.external_run_id else None
        allocation_proven = bool(attempt.execution_started or attempt.execution_completed or attempt.collected_at
            or (remote is not None and remote.machine_id == attempt.machine_id
                and remote.job_id == job.job_id and remote.work_unit_id == unit.work_unit_id
                and remote.message != "status not published yet"))
        if allocation_proven and attempt.external_run_id and not attempt.remote_run_allocated:
            fields.append("remote_run_allocated")
        if (
            allocation_proven and attempt.external_run_id
            and attempt.dispatch_reservation_id
            and not attempt.prepared
        ):
            fields.append("prepared")
        if not fields:
            return

        repaired_fields: list[str] = []

        def apply(current: JobEnvelope) -> None:
            repaired_fields.clear()
            current_unit = next(
                item for item in current.work_units if item.work_unit_id == unit.work_unit_id
            )
            current_attempt = next(
                item for item in current_unit.attempts if item.attempt_id == attempt_id
            )
            if not _attempt_observation_is_current(current_unit, current_attempt):
                return
            if current_attempt.external_run_id:
                if allocation_proven and not current_attempt.remote_run_allocated:
                    current_attempt.remote_run_allocated = True
                    repaired_fields.append("remote_run_allocated")
                if allocation_proven and current_attempt.dispatch_reservation_id and not current_attempt.prepared:
                    current_attempt.prepared = True
                    repaired_fields.append("prepared")

        self.repository.mutate_job(job.job_id, apply, hydrate_blobs=False)
        if not repaired_fields:
            return
        self.service._event(
            "attempt.execution_boundary_repaired",
            self.owner_id,
            "attempt",
            attempt_id,
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
            repaired_fields=repaired_fields,
        )

    @staticmethod
    def _is_uncertain_remote_recovery(unit: WorkUnit, attempt) -> bool:
        reason = attempt.failure_reason or unit.failure_reason or ""
        return bool(
            unit.status not in {WorkUnitStatus.COMPLETED, WorkUnitStatus.CANCELLED}
            and unit.attempts
            and attempt is unit.attempts[-1]
            and attempt.state == "failed"
            and attempt.failure_class == FailureClass.INFRASTRUCTURE
            and attempt.external_run_id
            and not attempt.execution_completed
            and reason.startswith("remote state remained uncertain:")
        )

    def _recover_uncertain_attempt(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        attempt_id: str,
    ) -> bool:
        attempt = next(item for item in unit.attempts if item.attempt_id == attempt_id)
        if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
            return True
        try:
            run = self.adapter_provider(attempt.machine_id or "").poll(attempt.external_run_id or "")
            if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
                return True
            self.repository.put_remote_run(run)
        except Exception as exc:
            if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
                return True
            self._mark_uncertain(
                job.job_id,
                unit.work_unit_id,
                attempt_id,
                str(exc),
            )
            return False
        if run.state in {RemoteRunState.STAGED, RemoteRunState.PREPARED, RemoteRunState.QUEUED}:
            self._mark_assigned(job.job_id, unit.work_unit_id, attempt_id, run)
        elif run.state == RemoteRunState.RUNNING:
            self._mark_running(job.job_id, unit.work_unit_id, attempt_id, run)
        elif run.state in {RemoteRunState.COMPLETED, RemoteRunState.COLLECTING}:
            if not self._queue_collection(job, unit, attempt_id, run):
                return False
        elif run.state in {
            RemoteRunState.FAILED,
            RemoteRunState.INTERRUPTED,
            RemoteRunState.CANCELLED,
        }:
            # The remote terminal state is now authoritative. The existing
            # retry policy may create a new Attempt later, but only after the
            # prior external run is known not to be active.
            pass
        else:
            return False
        self.service._event(
            "attempt.uncertain_infrastructure_recovered",
            self.owner_id,
            "attempt",
            attempt_id,
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
            external_run_id=attempt.external_run_id,
            remote_state=run.state.value,
        )
        return True

    def _cancel_attempt(self, job: JobEnvelope, unit: WorkUnit, attempt_id: str) -> bool:
        attempt = next(item for item in unit.attempts if item.attempt_id == attempt_id)
        if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
            return True
        try:
            self.adapter_provider(attempt.machine_id or "").cancel(attempt.external_run_id or "")
        except Exception as exc:
            self._mark_cancel_pending(job.job_id, unit.work_unit_id, attempt_id, str(exc))
            return False

        return self._record_attempt_cancelled(job, unit, attempt_id)

    @atomic_metadata
    def _record_attempt_cancelled(self, job: JobEnvelope, unit: WorkUnit, attempt_id: str) -> bool:
        cancelled = False
        def apply(current: JobEnvelope) -> None:
            nonlocal cancelled
            cancelled = False
            current_unit = next(item for item in current.work_units if item.work_unit_id == unit.work_unit_id)
            current_attempt = next(item for item in current_unit.attempts if item.attempt_id == attempt_id)
            if not _attempt_observation_is_current(current_unit, current_attempt):
                return
            current_attempt.state = "cancelled"
            current_attempt.finished_at = _utc_now()
            current_attempt.failure_class = FailureClass.CANCELLED
            self.service._compute_credits.settle_attempt(
                current, current_unit, current_attempt, outcome="cancelled",
                actor_id=self.owner_id,
            )
            cancelled = True

        self.repository.mutate_job(job.job_id, apply, hydrate_blobs=False, atomic_callback=True)
        if not cancelled:
            return True
        self.service._event(
            "attempt.cancelled",
            self.owner_id,
            "attempt",
            attempt_id,
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
        )
        return True

    def _mark_cancel_pending(
        self,
        job_id: str,
        work_unit_id: str,
        attempt_id: str,
        reason: str,
    ) -> None:
        marked = False
        def apply(job: JobEnvelope) -> None:
            nonlocal marked
            marked = False
            unit = next(item for item in job.work_units if item.work_unit_id == work_unit_id)
            attempt = next(item for item in unit.attempts if item.attempt_id == attempt_id)
            if not _attempt_observation_is_current(unit, attempt):
                return
            attempt.state = "cancel_pending"
            attempt.failure_reason = reason
            unit.status = WorkUnitStatus.CANCELLED
            unit.failure_reason = reason
            marked = True

        self.repository.mutate_job(job_id, apply, hydrate_blobs=False)
        if not marked:
            return
        self.service._event(
            "attempt.cancel_pending",
            self.owner_id,
            "attempt",
            attempt_id,
            job_id=job_id,
            work_unit_id=work_unit_id,
            reason=reason,
        )

    def _poll_attempt(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        attempt_id: str,
        *,
        allow_uncertain: bool = True,
    ) -> bool:
        attempt = next(item for item in unit.attempts if item.attempt_id == attempt_id)
        if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
            return True
        try:
            run = self.adapter_provider(attempt.machine_id or "").poll(attempt.external_run_id or "")
            if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
                return True
            missing_status = (run.state == RemoteRunState.STAGED
                              and run.message == "status not published yet" and run.job_id == "unknown")
            if not missing_status:
                if (run.machine_id != attempt.machine_id or run.job_id != job.job_id
                        or run.work_unit_id != unit.work_unit_id):
                    raise ValueError("remote observation identity mismatch")
                self.repository.put_remote_run(run)
                self._repair_execution_boundary_evidence(job, unit, attempt_id)
            # An absent status file must never overwrite previously proven
            # RUNNING/COMPLETED evidence with a fabricated STAGED record.
        except Exception as exc:
            if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
                return True
            if allow_uncertain:
                self._mark_uncertain(job.job_id, unit.work_unit_id, attempt_id, str(exc))
            else:
                self.service._event(
                    "attempt.observation_deferred",
                    self.owner_id,
                    "attempt",
                    attempt_id,
                    job_id=job.job_id,
                    work_unit_id=unit.work_unit_id,
                    reason=str(exc),
                )
            return False

        if run.message == "status not published yet" and run.job_id == "unknown":
            # Absence is neither a negative acknowledgement nor a terminal
            # result. Keep the same external identity, even across restarts.
            self._mark_uncertain(job.job_id, unit.work_unit_id, attempt_id,
                                 "submission delivery unknown: status not published yet")
            return False
        if run.state in {RemoteRunState.STAGED, RemoteRunState.PREPARED, RemoteRunState.QUEUED}:
            if self._maybe_reactivate_standby(job, unit, attempt, run):
                return True
            self._mark_assigned(job.job_id, unit.work_unit_id, attempt_id, run)
            # A known remote queue is reconciled successfully.  It occupies a
            # slot, but it is not a pending/uncertain observation and must not
            # block Dispatcher startup or inflate the health warning count.
            return True
        elif run.state == RemoteRunState.RUNNING:
            self._mark_running(job.job_id, unit.work_unit_id, attempt_id, run)
            return True
        if run.state in {RemoteRunState.UNCERTAIN, RemoteRunState.RECONCILE_PENDING}:
            self._mark_uncertain(job.job_id, unit.work_unit_id, attempt_id, run.message)
            return False
        if run.state in {RemoteRunState.COMPLETED, RemoteRunState.FAILED,
                         RemoteRunState.CANCELLED, RemoteRunState.INTERRUPTED}:
            observed_end = _utc_now()
            def mark_observed_end(current):
                current_unit = next(u for u in current.work_units if u.work_unit_id == unit.work_unit_id)
                current_attempt = next(a for a in current_unit.attempts if a.attempt_id == attempt_id)
                if not _attempt_observation_is_current(current_unit, current_attempt):
                    return
                if current_attempt.execution_end_observed_at is None:
                    current_attempt.execution_end_observed_at = observed_end
            self.repository.mutate_job(job.job_id, mark_observed_end, hydrate_blobs=False)
        if run.state == RemoteRunState.CANCELLED:
            self._fail_observed_attempt(
                job.job_id, unit.work_unit_id, attempt_id,
                error=run.message or "remote run cancelled",
                failure_class=FailureClass.CANCELLED,
            )
            return True
        if run.state in {RemoteRunState.FAILED, RemoteRunState.INTERRUPTED}:
            failure_class = (
                FailureClass.INFRASTRUCTURE
                if run.state == RemoteRunState.INTERRUPTED
                else classify_remote_failure(run)
            )
            self._fail_observed_attempt(
                job.job_id, unit.work_unit_id, attempt_id,
                error=run.message or f"remote run {run.state.value}",
                failure_class=failure_class,
            )
            return True
        if run.state in {RemoteRunState.COMPLETED, RemoteRunState.COLLECTING}:
            queued = self._queue_collection(job, unit, attempt_id, run)
            if (
                not queued
                and unit.status == WorkUnitStatus.RECONCILE_PENDING
                and attempt.state == "reconcile_pending"
            ):
                return False
            # A known terminal run is observed successfully even when its
            # collection waits, unless an existing quarantine remains pending.
            return True
        return False

    def _attempt_is_current(self, job_id: str, work_unit_id: str, attempt_id: str) -> bool:
        """Check persisted identity before or after blocking remote I/O.

        This reduces obsolete I/O; aggregate mutations also check the identity
        transactionally, since a preflight check alone cannot close the race.
        """
        job = self.repository.get_operational_job(job_id)
        unit = (
            next((item for item in job.work_units if item.work_unit_id == work_unit_id), None)
            if job is not None else None
        )
        return bool(
            unit is not None
            and unit.attempts
            and unit.attempts[-1].attempt_id == attempt_id
            and unit.attempts[-1].state != "abandoned"
        )

    def _fail_observed_attempt(
        self, job_id: str, work_unit_id: str, attempt_id: str,
        *, error: str, failure_class: FailureClass,
    ) -> None:
        try:
            self.service.fail_unit(
                job_id, work_unit_id, error=error, failure_class=failure_class,
                actor_id=self.owner_id, expected_attempt_id=attempt_id,
            )
        except ValueError:
            if self._attempt_is_current(job_id, work_unit_id, attempt_id):
                raise

    def _maybe_reactivate_standby(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        attempt,
        run: RemoteRunRecord,
    ) -> bool:
        """Retry a prepared standby activation without creating an Attempt.

        A worker can acknowledge an activation while its local queue is still
        settling.  Reissuing the fixed activation record is idempotent and
        prevents a slot from remaining assigned forever.  Normal submissions
        are excluded: only persisted standby provenance (or the legacy
        reservation-shaped external id) is eligible.
        """
        external_run_id = attempt.external_run_id or ""
        if not external_run_id or not (
            getattr(attempt, "dispatch_reservation_id", None)
            or "-reservation-" in external_run_id
        ):
            return False
        config = self.repository.get_machine_execution_config(attempt.machine_id or "")
        if config is not None and (not config.enabled or not self.service.runtime_policy.accepts_worker_runtime(config.runtime_version)):
            return False  # Recovery-only poll/collect cannot activate a disabled worker.
        if self.io_stop_event.is_set() or self._lease_lost or self._drain_requested():
            return False
        now = _utc_now()
        assigned_at = _aware(
            getattr(attempt, "assigned_at", None)
            or attempt.last_observed_at
            or attempt.started_at
        )
        if assigned_at is None or now - assigned_at < timedelta(
            seconds=self.standby_activation_retry_after_s
        ):
            return False
        requested_at = _aware(getattr(attempt, "activation_requested_at", None))
        retry_count = int(getattr(attempt, "activation_retry_count", 0) or 0)
        age_s = max(0.0, (now - assigned_at).total_seconds())
        if retry_count >= self.max_standby_activation_retries:
            if requested_at is not None and now - requested_at < timedelta(
                seconds=self.standby_activation_retry_after_s
            ):
                return False
            if age_s >= self.standby_activation_stall_after_s:
                def mark_stall_check(current: JobEnvelope) -> None:
                    current_unit = next(item for item in current.work_units if item.work_unit_id == unit.work_unit_id)
                    current_attempt = next(item for item in current_unit.attempts if item.attempt_id == attempt.attempt_id)
                    if not _attempt_observation_is_current(current_unit, current_attempt):
                        return
                    current_attempt.activation_requested_at = now

                self.repository.mutate_job(job.job_id, mark_stall_check, hydrate_blobs=False)
                self._retire_stalled_standby(job, unit, attempt, run)
                return True
            return False
        if (
            requested_at is not None
            and now - requested_at < timedelta(seconds=self.standby_activation_retry_after_s)
        ):
            return False

        def mark_retry(current: JobEnvelope) -> None:
            nonlocal activation_allowed
            activation_allowed = False
            current_unit = next(item for item in current.work_units if item.work_unit_id == unit.work_unit_id)
            current_attempt = next(item for item in current_unit.attempts if item.attempt_id == attempt.attempt_id)
            if (
                _cancellation_won(current, current_unit, current_attempt)
                or current_attempt.state != "assigned"
                or current_attempt.external_run_id != external_run_id
            ):
                return
            current_attempt.activation_requested_at = now
            current_attempt.activation_retry_count = min(
                self.max_standby_activation_retries,
                int(getattr(current_attempt, "activation_retry_count", 0) or 0) + 1,
            )
            activation_allowed = True

        activation_allowed = False
        self.repository.mutate_job(job.job_id, mark_retry, hydrate_blobs=False)
        if not activation_allowed:
            return True
        try:
            self._assert_publication_lease()
            self.adapter_provider(attempt.machine_id or "").activate(external_run_id)
        except Exception as exc:
            self.service._event(
                "attempt.standby_activation_retry_failed",
                self.owner_id,
                "attempt",
                attempt.attempt_id,
                job_id=job.job_id,
                work_unit_id=unit.work_unit_id,
                machine_id=attempt.machine_id,
                retry_count=retry_count + 1,
                error=f"{type(exc).__name__}: {exc}",
            )
            return False
        self.service._event(
            "attempt.standby_activation_retried",
            self.owner_id,
            "attempt",
            attempt.attempt_id,
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
            machine_id=attempt.machine_id,
            remote_state=run.state.value,
            retry_count=retry_count + 1,
        )
        return False

    def _retire_stalled_standby(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        attempt,
        run: RemoteRunRecord,
    ) -> None:
        """Release a known queued/prepared standby that never starts.

        This path is limited to an explicit remote queue state after all
        idempotent activation retries.  It cancels that same external run,
        records an infrastructure failure, and lets the normal bounded retry
        policy requeue the Unit; it never creates a second Attempt in place.
        """
        external_run_id = attempt.external_run_id or ""
        if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt.attempt_id):
            return
        try:
            adapter = self.adapter_provider(attempt.machine_id or "")
            adapter.cancel(external_run_id)
            acknowledgement = adapter.poll(external_run_id)
            if (acknowledgement.external_run_id != external_run_id
                    or acknowledgement.machine_id != attempt.machine_id
                    or acknowledgement.job_id != job.job_id
                    or acknowledgement.work_unit_id != unit.work_unit_id
                    or acknowledgement.request_hash != run.request_hash
                    or acknowledgement.state != RemoteRunState.CANCELLED
                    or not acknowledgement.message.startswith("cancelled before launch")
                    or acknowledgement.artifacts_available
                    or attempt.execution_started or attempt.execution_completed):
                # A posted cancel is not proof of process exit. Retain the
                # original Attempt/slot until that exact unstarted run agrees.
                return
        except Exception as exc:
            self.service._event(
                "attempt.standby_activation_stall_observed",
                self.owner_id,
                "attempt",
                attempt.attempt_id,
                job_id=job.job_id,
                work_unit_id=unit.work_unit_id,
                machine_id=attempt.machine_id,
                remote_state=run.state.value,
                error=f"{type(exc).__name__}: {exc}",
            )
            return
        self._fail_observed_attempt(
            job.job_id, unit.work_unit_id, attempt.attempt_id,
            error=(
                "standby activation stalled after bounded retries; "
                f"remote state remained {run.state.value}"
            ),
            failure_class=FailureClass.INFRASTRUCTURE,
        )
        self.service._event(
            "attempt.standby_activation_stalled",
            self.owner_id,
            "attempt",
            attempt.attempt_id,
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
            machine_id=attempt.machine_id,
            remote_state=run.state.value,
            retry_count=int(getattr(attempt, "activation_retry_count", 0) or 0),
        )

    def _reap_collections(self) -> None:
        with self._collection_lock:
            completed = [key for key, (_, future) in self._collection_futures.items() if future.done()]
            for key in completed:
                _, future = self._collection_futures.pop(key)
                try:
                    future.result()
                except Exception as exc:
                    self.service._event(
                        "attempt.collection_worker_failed",
                        self.owner_id,
                        "attempt",
                        key[2],
                        job_id=key[0],
                        work_unit_id=key[1],
                        error=f"{type(exc).__name__}: {exc}",
                    )

    def _queue_collection(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        attempt_id: str,
        run: RemoteRunRecord,
    ) -> bool:
        if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
            return True
        key = (job.job_id, unit.work_unit_id, attempt_id)
        attempt = next(item for item in unit.attempts if item.attempt_id == attempt_id)
        machine_id = attempt.machine_id or ""
        with self._collection_lock:
            if key in self._collection_futures:
                return True
            if self._collection_storage_retry_after.get(key, 0) > time.monotonic():
                return False
            self._collection_storage_retry_after.pop(key, None)
            collector_busy = sum(
                pending_machine == machine_id and not future.done()
                for pending_machine, future in self._collection_futures.values()
            ) >= 1

            def mark_collecting(current: JobEnvelope) -> None:
                nonlocal collection_allowed
                collection_allowed = False
                current_unit = next(item for item in current.work_units if item.work_unit_id == unit.work_unit_id)
                current_attempt = next(item for item in current_unit.attempts if item.attempt_id == attempt_id)
                if _cancellation_won(current, current_unit, current_attempt):
                    return
                if collector_busy and (
                    current_unit.status == WorkUnitStatus.RECONCILE_PENDING
                    or current_attempt.state in {"reconcile_pending", "uncertain"}
                ):
                    return  # Preserve existing quarantine until collection can retry.
                current_attempt.state = "collecting"
                current_attempt.last_observed_at = _utc_now()
                current_unit.status = WorkUnitStatus.COLLECTING
                collection_allowed = True

            collection_allowed = False
            self.repository.mutate_job(job.job_id, mark_collecting, hydrate_blobs=False)
            if collector_busy:
                # Execution has ended even while its original result waits for
                # transfer. Keep reconciliation identity without a compute slot.
                return False
            if not collection_allowed:
                return True
            future = self._collection_pool.submit(
                self._collect_attempt,
                job,
                unit,
                attempt_id,
                run,
            )
            self._collection_futures[key] = (machine_id, future)
        self.service._event(
            "attempt.collection_started",
            self.owner_id,
            "attempt",
            attempt_id,
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
            machine_id=machine_id,
        )
        if (
            machine_id
            and self._pipeline is None
            and self.status.accepting_assignments
            and not self._lease_lost
            and not self._drain_requested()
        ):
            self._activate_ready_reservations(machine_id=machine_id)
        self.wake()
        return True

    def _mark_running(
        self,
        job_id: str,
        work_unit_id: str,
        attempt_id: str,
        run: RemoteRunRecord,
    ) -> None:
        def apply(job: JobEnvelope) -> None:
            unit = next(item for item in job.work_units if item.work_unit_id == work_unit_id)
            attempt = next(item for item in unit.attempts if item.attempt_id == attempt_id)
            if _cancellation_won(job, unit, attempt):
                return
            now = _utc_now()
            attempt.state = "running"
            attempt.execution_started = True
            attempt.execution_completed = False
            attempt.started_at = attempt.started_at or now
            attempt.finished_at = None
            attempt.last_observed_at = now
            attempt.failure_reason = None
            attempt.failure_class = None
            unit.status = WorkUnitStatus.RUNNING
            unit.assigned_machine_id = run.machine_id or attempt.machine_id
            unit.failure_reason = None
            unit.dispatch_failure_count = 0
            unit.dispatch_not_before_at = None
            unit.progress_percent = run.progress_percent
            unit.completed_items = run.completed_items
            unit.total_items = run.total_items
            unit.eta_s = run.eta_s
            unit.progress_message = run.message
            job.status = JobStatus.RUNNING

        self.repository.mutate_job(job_id, apply, hydrate_blobs=False)

    def _mark_assigned(
        self,
        job_id: str,
        work_unit_id: str,
        attempt_id: str,
        run: RemoteRunRecord,
    ) -> None:
        """Keep a remotely queued run out of the solving/CPU activity count.

        The SSH adapter can acknowledge a request before the worker has
        created its Job Object.  Treating that acknowledgement as ``running``
        made Runs/Fleet disagree with heartbeat process telemetry and hid
        queueing behind a false active Unit.  The attempt still occupies its
        scheduler slot through the ``assigned`` state, but ETA and CPU
        activity begin only after the worker reports ``running``.
        """
        def apply(job: JobEnvelope) -> None:
            unit = next(item for item in job.work_units if item.work_unit_id == work_unit_id)
            attempt = next(item for item in unit.attempts if item.attempt_id == attempt_id)
            if _cancellation_won(job, unit, attempt):
                return
            now = _utc_now()
            attempt.state = "assigned"
            attempt.execution_completed = False
            attempt.assigned_at = attempt.assigned_at or now
            attempt.finished_at = None
            attempt.last_observed_at = now
            attempt.failure_reason = None
            attempt.failure_class = None
            unit.status = WorkUnitStatus.ASSIGNED
            unit.assigned_machine_id = run.machine_id or attempt.machine_id
            unit.failure_reason = None
            unit.dispatch_failure_count = 0
            unit.dispatch_not_before_at = None
            unit.progress_percent = run.progress_percent
            unit.completed_items = run.completed_items
            unit.total_items = run.total_items
            unit.eta_s = None
            unit.progress_message = run.message or "等待远端执行器启动"
            job.status = JobStatus.RUNNING

        self.repository.mutate_job(job_id, apply, hydrate_blobs=False)

    def _mark_uncertain(self, job_id: str, work_unit_id: str, attempt_id: str, reason: str) -> None:
        changed = False

        def apply(job: JobEnvelope) -> None:
            nonlocal changed
            changed = False
            unit = next(item for item in job.work_units if item.work_unit_id == work_unit_id)
            attempt = next(item for item in unit.attempts if item.attempt_id == attempt_id)
            if _cancellation_won(job, unit, attempt):
                return
            attempt.state = "reconcile_pending"
            attempt.failure_reason = reason
            unit.status = WorkUnitStatus.RECONCILE_PENDING
            unit.failure_reason = reason
            job.status = JobStatus.RUNNING
            changed = True

        self.repository.mutate_job(job_id, apply, hydrate_blobs=False)
        if not changed:
            return
        self.service._event(
            "attempt.reconcile_pending",
            self.owner_id,
            "attempt",
            attempt_id,
            job_id=job_id,
            work_unit_id=work_unit_id,
            reason=reason,
        )

    def _record_collection_failure(
        self,
        attempt_id: str,
        reason: str,
        *,
        machine_id: str | None = None,
        transport: bool = False,
        job_id: str | None = None,
        work_unit_id: str | None = None,
    ) -> bool:
        """Persist repeated collection failures and stop new assignments.

        The alert ID binds one attempt and a normalized error signature, so a
        Dispatcher restart cannot reset the retry counter or resume a revision
        loop. A later failure outside the short window starts a fresh count.

        Transport-class failures (typed SSH transport errors, command timeouts,
        or connection markers) are machine-scoped: the failing machine is
        quarantined by the reconcile-pending and telemetry gates and only the
        alert escalates. Integrity-class or unknown failures keep the global
        circuit because they may indicate a systemic, fleet-wide risk.
        """
        if (job_id is None) != (work_unit_id is None):
            raise ValueError("collection failure context requires both Job and WorkUnit")
        now = _utc_now()
        signature = hashlib.sha256(reason.encode("utf-8", errors="replace")).hexdigest()
        alert_id = f"collection:{attempt_id}:{signature[:24]}"
        alert = self.repository.get_alert(alert_id)
        last_seen = _aware(alert.last_seen_at) if alert is not None else None
        within_window = (
            last_seen is not None
            and now - last_seen <= timedelta(seconds=self.collection_circuit_window_s)
        )
        if alert is None or not within_window:
            alert = AlertRecord(
                alert_id=alert_id,
                severity=AlertSeverity.WARNING,
                subject_type="attempt",
                subject_id=attempt_id,
                kind="collection_failure",
                message="collection failure awaiting bounded retry",
                reason=reason[:500],
                first_seen_at=now,
                last_seen_at=now,
            )
        else:
            alert.last_seen_at = now
            alert.occurrence_count += 1
            alert.reason = reason[:500]
            if alert.status == AlertStatus.RESOLVED:
                alert.status = AlertStatus.ACTIVE
                alert.resolved_at = None

        circuit_event = None
        latch_circuit = False
        if alert.occurrence_count >= self.collection_circuit_failure_limit:
            alert.severity = AlertSeverity.CRITICAL
            alert.kind = "collection_circuit_open"
            if (
                transport
                and machine_id
                and os.environ.get("RCN_COLLECTION_CIRCUIT_GLOBAL", "") != "1"
            ):
                # Transport evidence is machine-scoped by definition: the unit
                # is already reconcile_pending, which quarantines exactly this
                # machine in schedule_once, and stale telemetry excludes it
                # from placement. Healthy machines must keep receiving work,
                # so only the alert escalates — the global circuit stays open.
                # RCN_COLLECTION_CIRCUIT_GLOBAL=1 restores the legacy global
                # drain without a rollback deployment.
                alert.message = (
                    "repeated transport collection failure quarantined machine "
                    f"{machine_id}; Dispatcher remains open"
                )
                circuit_event = "dispatcher.collection_circuit_machine_quarantined"
            else:
                alert.message = "repeated collection failure opened Dispatcher circuit"
                circuit_event = "dispatcher.collection_circuit_open"
                latch_circuit = True
        if job_id is not None and work_unit_id is not None:
            if not self.repository.put_attempt_collection_alert(
                alert, job_id=job_id, work_unit_id=work_unit_id,
                expected_attempt_id=attempt_id, latch_circuit=latch_circuit,
            ):
                return False
        else:
            # Direct legacy/operator fixtures without an execution context
            # retain the original alert and circuit behavior.
            self.repository.put_alert(alert)
            if latch_circuit:
                self.repository.latch_collection_circuit(alert.alert_id)
        if circuit_event:
            details = {"machine_id": machine_id} if transport and not latch_circuit else {}
            self.service._event(
                circuit_event,
                self.owner_id,
                "attempt",
                attempt_id,
                error_signature=signature,
                occurrences=alert.occurrence_count,
                window_s=self.collection_circuit_window_s,
                **details,
            )
        return True

    def _resolve_collection_alerts(self, attempt_id: str) -> None:
        """Close stale collection alerts after the same Attempt is collected."""
        resolved_ids = self.repository.resolve_proven_collection_alerts(attempt_id).get(attempt_id, [])
        if resolved_ids:
            self.service._event(
                "attempt.collection_alerts_resolved",
                self.owner_id,
                "attempt",
                attempt_id,
                alert_ids=resolved_ids,
                reason="artifact collection completed successfully",
            )
            self._maybe_auto_resume_collection_circuit()

    def _maybe_auto_resume_collection_circuit(self) -> None:
        """Recover from positively verified causes without removing operator markers."""
        def externally_blocked() -> bool:
            return any(value and Path(value).exists() for value in (
                os.environ.get("RCN_DISPATCHER_DRAIN_FILE", ""),
                os.environ.get("RCN_DISPATCHER_STOP_FILE", ""),
            ))
        status = self.repository.resume_proven_collection_circuit(
            limit=self.collection_circuit_auto_resume_limit, externally_blocked=externally_blocked,
        )
        if status is None:
            return
        self._apply_control_state(status)
        self.service._event(
            "dispatcher.collection_circuit_auto_resumed",
            self.owner_id,
            "dispatcher",
            "dispatcher",
            auto_resume_count=status.collection_circuit_auto_resume_count,
        )

    def _reconcile_collection_alerts(self) -> None:
        """Resolve alerts left active when collection recovered before an upgrade."""
        for attempt_id, alert_ids in self.repository.resolve_proven_collection_alerts().items():
            self.service._event(
                "attempt.collection_alerts_resolved", self.owner_id, "attempt", attempt_id,
                alert_ids=alert_ids, reason="persisted artifact collection verified after failure",
            )
        self._maybe_auto_resume_collection_circuit()

    def _collect_attempt(
        self,
        job: JobEnvelope,
        unit: WorkUnit,
        attempt_id: str,
        run: RemoteRunRecord,
    ) -> bool:
        if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
            return True
        # Recovery scans intentionally keep blob-backed scientific payloads
        # opaque.  Collection is the one path that needs item provenance, so
        # hydrate only this Job on demand instead of retaining full payloads
        # for every recovery candidate.
        hydrated_job = self.repository.get_job(job.job_id)
        if hydrated_job is not None:
            hydrated_unit = next(
                (candidate for candidate in hydrated_job.work_units
                 if candidate.work_unit_id == unit.work_unit_id),
                None,
            )
            if hydrated_unit is not None:
                job, unit = hydrated_job, hydrated_unit
        attempt = next(item for item in unit.attempts if item.attempt_id == attempt_id)
        if self.staging_provider is None:
            self._mark_uncertain(
                job.job_id,
                unit.work_unit_id,
                attempt_id,
                "origin staging provider is not configured",
            )
            # A collection blocker can be cleared by a later origin or
            # transport event. Wake the long-running loop immediately rather
            # than waiting for its bounded polling interval.
            self.wake()
            return False
        try:
            try:
                destination = self.staging_provider(job, unit, attempt_id).resolve()
            except TypeError:
                # Preserve legacy fixture hooks; production includes Attempt.
                destination = self.staging_provider(job, unit).resolve()  # type: ignore[misc]
            destination.mkdir(parents=True, exist_ok=True)
            if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
                return True
            self.adapter_provider(attempt.machine_id or "").collect_artifacts(
                attempt.external_run_id or "",
                str(destination),
            )
            if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
                return True
            manifest = self._validated_manifest(
                destination,
                job,
                unit,
                attempt_id,
            )
        except (CollectionCapacityUnavailable, StorageRootError, VolumeHolderBusy) as exc:
            if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
                return True
            key = (job.job_id, unit.work_unit_id, attempt_id)
            with self._collection_lock:
                report = self._collection_storage_retry_after.get(key, 0) <= time.monotonic()
                self._collection_storage_retry_after[key] = time.monotonic() + 30
            if report:
                self.service._event(
                    "attempt.collection_storage_deferred", self.owner_id, "attempt", attempt_id,
                    job_id=job.job_id, work_unit_id=unit.work_unit_id, machine_id=attempt.machine_id,
                    external_run_id=attempt.external_run_id, required_bytes=getattr(exc, "required_bytes", None),
                    free_bytes=getattr(exc, "free_bytes", None), reserved_bytes=getattr(exc, "reserved_bytes", None),
                    reserve_bytes=getattr(exc, "reserve_bytes", None), reason_code=getattr(exc, "reason_code", "storage_capacity_unavailable"),
                    retry_after_s=30, execution_replayed=False,
                )
            return False
        except Exception as exc:
            if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
                return True
            reason = f"collection failed: {exc}"
            recorded = self._record_collection_failure(
                attempt_id,
                reason,
                machine_id=attempt.machine_id or None,
                transport=_is_transport_collection_failure(exc),
                job_id=job.job_id,
                work_unit_id=unit.work_unit_id,
            )
            if not recorded:
                return True
            self._mark_uncertain(job.job_id, unit.work_unit_id, attempt_id, reason)
            self.wake()
            return False
        with self._collection_lock:
            self._collection_storage_retry_after.pop((job.job_id, unit.work_unit_id, attempt_id), None)
        try:
            self.service.complete_unit(
                job.job_id,
                unit.work_unit_id,
                manifest=manifest,
                duration_s=max(0.0, (_utc_now() - (_aware(attempt.started_at) or _utc_now())).total_seconds()),
                actor_id=self.owner_id,
                attempt_id=attempt_id,
                expected_attempt_id=attempt_id,
            )
        except ValueError:
            if not self._attempt_is_current(job.job_id, unit.work_unit_id, attempt_id):
                return True
            raise

        collected = False
        def mark_collected(current: JobEnvelope) -> None:
            nonlocal collected
            collected = False
            completed_unit = next(item for item in current.work_units if item.work_unit_id == unit.work_unit_id)
            completed_attempt = next(item for item in completed_unit.attempts if item.attempt_id == attempt_id)
            if (
                not _attempt_observation_is_current(completed_unit, completed_attempt)
                or completed_attempt.state != "completed"
                or completed_unit.status != WorkUnitStatus.COMPLETED
            ):
                return
            completed_attempt.collected_at = _utc_now()
            collected = True

        self.repository.mutate_job(job.job_id, mark_collected, hydrate_blobs=False)
        if not collected:
            return True
        self._resolve_collection_alerts(attempt_id)
        self.service._event(
            "attempt.collected",
            self.owner_id,
            "attempt",
            attempt_id,
            job_id=job.job_id,
            work_unit_id=unit.work_unit_id,
            manifest_files=len(manifest.files),
        )
        # Completion can free a slot for a queued or prepared Unit. Do not
        # make the next assignment wait for the normal dispatcher interval.
        self.wake()
        return True

    def _validated_manifest(
        self,
        root: Path,
        job: JobEnvelope,
        unit: WorkUnit,
        attempt_id: str,
    ) -> ArtifactManifest:
        job_id = job.job_id
        work_unit_id = unit.work_unit_id
        candidates = sorted(root.rglob("*.json"))
        manifest: ArtifactManifest | None = None
        for path in candidates:
            try:
                payload = json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError):
                continue
            if payload.get("job_id") != job_id or payload.get("work_unit_id") != work_unit_id:
                continue
            # Remote Supervisor emits a transport manifest. Normalize it at
            # the origin boundary into the control-plane ArtifactManifest and
            # retain machine/runtime/attempt provenance in producer metadata.
            try:
                files = payload.get("files", [])
                if not isinstance(files, list):
                    raise ValueError("manifest files must be a list")
                profile = self.repository.get_profile(job.execution_profile_id)
                if profile is None:
                    raise ValueError("execution profile is unavailable")
                attempt = next(item for item in unit.attempts if item.attempt_id == attempt_id)
                study = payload.get("study") if isinstance(payload.get("study"), dict) else {}
                item_payload = {}
                raw_items = unit.payload.get("items") if isinstance(unit.payload, dict) else None
                if isinstance(raw_items, list) and raw_items and isinstance(raw_items[0], dict):
                    item_payload = raw_items[0].get("payload") or {}
                # Workbench materializes the effective Study descriptor but
                # keeps the originally requested value in item provenance.
                # Read both locations so legacy bundles remain compatible and
                # inherited values are not mislabeled as explicitly requested.
                if "requested_eigen_solver" in item_payload:
                    requested_eigen_solver = item_payload["requested_eigen_solver"]
                elif "requested_eigen_solver" in payload:
                    requested_eigen_solver = payload["requested_eigen_solver"]
                else:
                    requested_eigen_solver = study.get("eigen_solver")
                effective_eigen_solver = (
                    payload.get("effective_eigen_solver")
                    or item_payload.get("effective_eigen_solver")
                )
                producer = {
                    "machine_id": attempt.machine_id or "unknown",
                    "runtime_version": str(payload.get("runtime_version") or "unknown"),
                    "attempt_id": attempt_id,
                    "external_run_id": attempt.external_run_id or "",
                    "solver_variant": attempt.solver_variant.value,
                    "solver_approval_id": attempt.solver_approval_id or "",
                    "transport_manifest": path.name,
                }
                if requested_eigen_solver is not None:
                    producer["requested_eigen_solver"] = json.dumps(
                        requested_eigen_solver, sort_keys=True, separators=(",", ":")
                    )
                if effective_eigen_solver is not None:
                    producer["effective_eigen_solver"] = json.dumps(
                        effective_eigen_solver, sort_keys=True, separators=(",", ":")
                    )
                for key in ("eigen_solver_source", "eigen_solver_inherited_fields"):
                    value = payload.get(key)
                    if value is None:
                        value = item_payload.get(key)
                    if value is not None:
                        producer[key] = (
                            json.dumps(value, sort_keys=True, separators=(",", ":"))
                            if isinstance(value, (dict, list))
                            else str(value)
                        )
                for key in ("template_sha256", "source_spec_sha256", "template_inspection_sha256"):
                    value = payload.get(key) or item_payload.get(key)
                    if value is not None:
                        producer[key] = str(value)
                candidate = ArtifactManifest(
                    job_id=job_id,
                    work_unit_id=work_unit_id,
                    files=files,
                    output_schema=profile.output_schema,
                    item_provenance=payload.get("item_provenance", []),
                    producer=producer,
                )
            except (TypeError, ValueError):
                candidate = None
            if candidate is not None:
                manifest = candidate
                break
        if manifest is None:
            raise ValueError("collected output does not contain a matching artifact manifest")
        for record in manifest.files:
            path = (root / record.relative_path).resolve()
            if root not in path.parents:
                raise ValueError(f"manifest path escapes origin staging: {record.relative_path}")
            if not path.is_file() or path.stat().st_size != record.size_bytes:
                raise ValueError(f"manifest size mismatch: {record.relative_path}")
            if sha256_file(path) != record.sha256:
                raise ValueError(f"manifest hash mismatch: {record.relative_path}")
        return manifest
