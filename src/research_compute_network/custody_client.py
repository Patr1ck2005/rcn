"""Origin-adapter Unit receiver and existing-dataset byte attestation.

The caller supplies its registered local destination and original Job/manifest.
HTTP transport, per-file resume, full SHA verification and no-clobber publishing
reuse OriginTransferClient. No remote response can choose a local root.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from .hashing import canonical_json_bytes, sha256_value
from .models import ArtifactManifest
from .origin_transfer import identifier, managed_path, publish_new_file, verify_file
from .origin_transfer_client import OriginTransferClient
from .scientific_retention import ScientificCustodyReceipt, ScientificExportAcceptance
from .storage_lifecycle import CustodyLocation, LifecycleError, UnitCustodyReceipt, inventory_sha256
from .storage_ops import _sync_directory


@dataclass(frozen=True)
class RegisteredCustodyDestination:
    """An adapter-owned registration, verified again before publication/receipt.

    ``validate`` must check the adapter's authoritative host/store/volume and
    generation registration and return this exact root. RCN StoreBinding can
    provide that check through ``from_store_binding``. No root is auto-enrolled.
    """

    root: Path
    location: CustodyLocation
    validate: Callable[[], Path]

    @classmethod
    def from_store_binding(cls, binding):
        if binding is None:
            raise LifecycleError("custody_destination_unregistered")
        volume = binding.volume_identity
        return cls(Path(binding.root), CustodyLocation(host_id=binding.host_id,
            store_id=binding.store_id, volume_id=volume.volume_id,
            generation=str(binding.generation), physical_device_id=volume.physical_device_id), binding.validate)

    def check(self) -> Path:
        root = Path(self.root)
        if not root.is_absolute() or not callable(self.validate) or not isinstance(self.location, CustodyLocation):
            raise LifecycleError("custody_destination_unregistered")
        current = Path(self.validate())
        if not current.is_absolute() or current != root:
            raise LifecycleError("custody_destination_binding_changed")
        managed_path(root, ".custody-check")
        if not root.is_dir():
            raise LifecycleError("custody_destination_unavailable")
        return root


@dataclass(frozen=True)
class CustodyReceiveResult:
    receipt: UnitCustodyReceipt
    receipt_id: str
    directory: Path
    already_present: bool


@dataclass(frozen=True)
class ScientificCustodyResult:
    receipt: ScientificCustodyReceipt
    receipt_id: str
    directory: Path
    already_present: bool


class _DestinationCheckedResponse:
    def __init__(self, response, validate):
        self.response, self.validate = response, validate

    def __getattr__(self, name):
        return getattr(self.response, name)

    def __enter__(self):
        self.response.__enter__()
        return self

    def __exit__(self, exc_type, exc, traceback):
        result = self.response.__exit__(exc_type, exc, traceback)
        if exc_type is None:
            # OriginTransferClient publishes after its response context closes.
            # Recheck the registered store at that existing publication gate.
            self.validate()
        return result


class _OneUnitTransfer(OriginTransferClient):
    """Adapt only the existing all-Unit index contract, retaining its transport."""
    def __init__(self, transfer, job_id, unit_id, attempt_id, manifest_sha256, validate):
        self.transfer = transfer
        self.index_path = f"/v1/jobs/{job_id}/origin-results"
        self.job_id, self.unit_id = job_id, unit_id
        self.attempt_id, self.manifest_sha256 = attempt_id, manifest_sha256
        self.validate = validate

    def require_available(self):
        return self.transfer.require_available()

    def _open(self, path, **kwargs):
        self.validate()
        response = self.transfer._open(path, **kwargs)
        if path != self.index_path:
            return _DestinationCheckedResponse(response, self.validate)
        with response:
            index = self.transfer._read_json(response)
        if index.get("job_id") != self.job_id or not isinstance(index.get("units"), list):
            raise LifecycleError("custody_result_index_mismatch")
        entries = [entry for entry in index["units"] if entry.get("work_unit_id") == self.unit_id]
        if (len(entries) != 1 or entries[0].get("attempt_id") != self.attempt_id
            or entries[0].get("manifest_sha256") != self.manifest_sha256):
            raise LifecycleError("custody_result_index_mismatch")
        self.validate()
        return io.BytesIO(canonical_json_bytes({"job_id": self.job_id, "units": entries}))


class OriginCustodyClient:
    def __init__(self, client, *, destination: RegisteredCustodyDestination | None = None):
        if not isinstance(destination, RegisteredCustodyDestination):
            raise LifecycleError("custody_destination_unregistered")
        destination.check()
        self.destination = destination
        self.transfer = client if isinstance(client, OriginTransferClient) else OriginTransferClient(client)
        if not self.transfer.client.token:
            raise LifecycleError("authenticated_adapter_token_required")

    def _write_immutable(self, path, payload):
        root = self.destination.check()
        path.relative_to(root)
        managed_path(root, path.relative_to(root).as_posix())
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = canonical_json_bytes(payload)
        descriptor, name = tempfile.mkstemp(prefix=".custody-", suffix=".partial", dir=path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            self.destination.check()
            managed_path(root, path.relative_to(root).as_posix())
            try:
                publish_new_file(temporary, path)
            except FileExistsError:
                if path.read_bytes() != raw:
                    raise LifecycleError("custody_idempotency_key_conflict")
            self._sync_parents(path.parent, root)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _sync_parents(directory, root):
        # Existing RCN convention: file fsync on Windows; directory fsync on
        # POSIX. This does not claim Windows supports POSIX directory handles.
        directory.relative_to(root)
        while True:
            _sync_directory(directory)
            if directory == root:
                break
            directory = directory.parent

    def _existing_directory(self, directory: str | Path) -> Path:
        """Check an adapter-supplied directory without enrolling a new root."""
        root = self.destination.check()
        directory = Path(directory)
        try:
            relative = directory.relative_to(root) if directory.is_absolute() else directory
        except ValueError as exc:
            raise LifecycleError("custody_directory_outside_registered_root") from exc
        checked = root if relative == Path(".") else managed_path(root, relative.as_posix())
        # Check even the root itself for links/reparse points.
        managed_path(checked, ".custody-check")
        if not checked.is_dir():
            raise LifecycleError("custody_directory_unavailable")
        return checked

    def _verify_files_and_sync(self, directory, files):
        root = self.destination.check()
        directory = self._existing_directory(directory)
        for record in files:
            self.destination.check()
            path = managed_path(directory, record.relative_path)
            before = path.stat()
            verify_file(path, record.size_bytes, record.sha256)
            # Use a write-capable Windows handle for FlushFileBuffers without
            # changing bytes; POSIX also permits fsync of a read-only handle.
            with path.open("r+b" if os.name == "nt" else "rb") as stream:
                os.fsync(stream.fileno())
            after = path.stat()
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise LifecycleError("custody_source_changed_during_verification")
            self._sync_parents(path.parent, root)
        self.destination.check()

    def _verify_and_sync(self, directory, manifest):
        self._verify_files_and_sync(directory, manifest.files)

    @staticmethod
    def _receipt_contract(receipt):
        return receipt.model_dump(mode="json", exclude={
            "verified_at", "actual_bytes_verified", "durable_publication"})

    def _persist_receipt(self, transaction, template):
        """Freeze verification time, including concurrent same-key retries."""
        receipt_path = managed_path(transaction, "receipt.json")
        contract = self._receipt_contract(template)
        model = type(template)
        if receipt_path.exists():
            receipt = model.model_validate_json(receipt_path.read_bytes())
            if self._receipt_contract(receipt) != contract:
                raise LifecycleError("custody_idempotency_key_conflict")
            return receipt
        receipt = template.model_copy(update={"verified_at": datetime.now(timezone.utc)})
        try:
            self._write_immutable(receipt_path, receipt.model_dump(mode="json"))
        except LifecycleError as exc:
            if exc.reason_code != "custody_idempotency_key_conflict":
                raise
            receipt = model.model_validate_json(receipt_path.read_bytes())
            if self._receipt_contract(receipt) != contract:
                raise
        return receipt

    def _publish_receipt(self, receipt, path, *, prefix="custody-",
                         id_field="receipt_id", payload_field="receipt"):
        import time
        from .client import RcnApiError

        self.destination.check()
        payload = receipt.model_dump(mode="json")
        raw = canonical_json_bytes(payload)
        headers = {"Content-Type": "application/json", "Content-Length": str(len(raw))}
        deadline = None
        for attempt in range(3):
            self.destination.check()
            try:
                options = {}
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise prior_clock_error
                    options["timeout"] = min(5, remaining)
                with self.transfer._open(path, method="POST", data=raw, headers=headers, **options) as response:
                    acknowledgement = self.transfer._read_json(response)
                break
            except RcnApiError as error:
                # Mixed/other errors, conflicts and missing error metadata are
                # not retryable. The persisted receipt's bytes and time stay
                # identical throughout this at-most-ten-second retry window.
                future_only = error.status == 422 and error.reason_code == "receipt_evidence_clock_skew"
                if not future_only or attempt == 2:
                    raise
                if deadline is None:
                    deadline = time.monotonic() + 10
                prior_clock_error = error
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(2, remaining))
                if time.monotonic() >= deadline:
                    raise
        expected_id = prefix + sha256_value(receipt.idempotency_key)[:32]
        if (acknowledgement.get(id_field) != expected_id
            or acknowledgement.get(payload_field) != payload
            or not isinstance(acknowledgement.get("already_present"), bool)
            or acknowledgement.get("revoked") is not False):
            raise LifecycleError("custody_acknowledgement_mismatch")
        self.destination.check()
        return expected_id, acknowledgement["already_present"]

    def _unit_template(self, *, job: dict, manifest: ArtifactManifest | dict,
                     producer_attempt_id: str, idempotency_key: str, verified_by: str,
                     adapter_id: str, adapter_version: str, adapter_build_sha256: str,
                     target_kind: Literal["origin_staging", "origin_dataset", "independent_archive"],
                     restore_ref: str) -> tuple[ArtifactManifest, UnitCustodyReceipt]:
        self.destination.check()
        manifest = ArtifactManifest.model_validate(manifest)
        job_id, unit_id = identifier(job["job_id"]), identifier(manifest.work_unit_id)
        identifier(producer_attempt_id)
        identifier(idempotency_key)
        if manifest.job_id != job_id or manifest.producer.get("attempt_id") != producer_attempt_id:
            raise LifecycleError("custody_original_producer_mismatch")
        units = [u for u in job.get("work_units", []) if u.get("work_unit_id") == unit_id]
        if len(units) != 1:
            raise LifecycleError("custody_unit_not_in_job")
        attempts = [a for a in units[0].get("attempts", []) if a.get("attempt_id") == producer_attempt_id]
        if (len(attempts) != 1 or attempts[0].get("state") != "completed"
            or not attempts[0].get("external_run_id") or not attempts[0].get("collected_at")):
            raise LifecycleError("custody_original_producer_mismatch")
        external = attempts[0]["external_run_id"]
        if manifest.producer.get("external_run_id", external) != external:
            raise LifecycleError("custody_original_producer_mismatch")
        if job.get("origin_adapter_id", "workbench") != adapter_id:
            raise LifecycleError("custody_adapter_binding_mismatch")
        manifest_digest = sha256_value(manifest.model_dump(mode="json"))
        inventory_digest = inventory_sha256(manifest.files)
        # Construct a validated template, but persist no byte-verification claim
        # until every actual local file has been read and durably published.
        template = UnitCustodyReceipt(idempotency_key=idempotency_key, project_id=job["project_id"],
            job_id=job_id, request_hash=job["request_hash"], work_unit_id=unit_id,
            producer_attempt_id=producer_attempt_id, producer_external_id=external,
            manifest_sha256=manifest_digest, files=manifest.files, inventory_sha256=inventory_digest,
            target=self.destination.location, target_kind=target_kind, verified_by=verified_by,
            adapter_id=adapter_id, adapter_version=adapter_version, adapter_build_sha256=adapter_build_sha256,
            verified_at=datetime.now(timezone.utc), verification_method="sha256_full_read",
            actual_bytes_verified=True, durable_publication=True, restore_ref=restore_ref)
        return manifest, template

    def receive_unit(self, *, job: dict, manifest: ArtifactManifest | dict,
                     producer_attempt_id: str, idempotency_key: str, verified_by: str,
                     adapter_id: str, adapter_version: str, adapter_build_sha256: str,
                     target_kind: Literal["origin_staging", "origin_dataset", "independent_archive"],
                     restore_ref: str) -> CustodyReceiveResult:
        """Receive one original completed producer while other Units may run.

        Reuse exactly this key/config after interrupted transfer or lost receipt
        acknowledgement. Previously published files are hashed, never replaced.
        A local immutable receipt freezes verified_at and is resent unchanged.
        """
        root = self.destination.check()
        manifest, template = self._unit_template(job=job, manifest=manifest,
            producer_attempt_id=producer_attempt_id, idempotency_key=idempotency_key,
            verified_by=verified_by, adapter_id=adapter_id, adapter_version=adapter_version,
            adapter_build_sha256=adapter_build_sha256, target_kind=target_kind, restore_ref=restore_ref)
        job_id, unit_id, manifest_digest = template.job_id, template.work_unit_id, template.manifest_sha256
        contract = self._receipt_contract(template)
        operation = {"receipt_contract": contract, "origin_submitter_id": identifier(job["origin_submitter_id"])}
        transaction = managed_path(root, ".custody-transactions", sha256_value(idempotency_key))
        operation_path = managed_path(transaction, "operation.json")
        self._write_immutable(operation_path, operation)
        transfer = _OneUnitTransfer(self.transfer, job_id, unit_id, producer_attempt_id,
                                    manifest_digest, self.destination.check)
        transfer.download_results(job, [manifest.model_dump(mode="json")], root)
        directory = managed_path(root, operation["origin_submitter_id"], "incoming", job_id, unit_id, producer_attempt_id)
        self._verify_and_sync(directory, manifest)
        receipt = self._persist_receipt(transaction, template)
        receipt_id, already_present = self._publish_receipt(receipt,
            f"/v1/jobs/{job_id}/units/{unit_id}/custody")
        return CustodyReceiveResult(receipt, receipt_id, directory, already_present)

    def attest_existing(self, *, job: dict, manifest: ArtifactManifest | dict,
                        directory: str | Path, producer_attempt_id: str, idempotency_key: str,
                        verified_by: str, adapter_id: str, adapter_version: str,
                        adapter_build_sha256: str,
                        target_kind: Literal["origin_staging", "origin_dataset", "independent_archive"],
                        restore_ref: str) -> CustodyReceiveResult:
        """Hash and flush an existing complete Unit without copying/downloading.

        ``directory`` is supplied by the local adapter and must be inside its
        registered destination. Extra dataset metadata may coexist there, but
        every file in the original manifest is required. Reusing this key also
        freezes the exact directory, original producer and receipt contract.
        """
        manifest, template = self._unit_template(job=job, manifest=manifest,
            producer_attempt_id=producer_attempt_id, idempotency_key=idempotency_key,
            verified_by=verified_by, adapter_id=adapter_id, adapter_version=adapter_version,
            adapter_build_sha256=adapter_build_sha256, target_kind=target_kind, restore_ref=restore_ref)
        directory = self._existing_directory(directory)
        root = self.destination.check()
        transaction = managed_path(root, ".custody-transactions", sha256_value(idempotency_key))
        operation = {"receipt_contract": self._receipt_contract(template),
            "origin_submitter_id": identifier(job["origin_submitter_id"]),
            "operation_kind": "attest_existing", "directory": directory.relative_to(root).as_posix()}
        self._write_immutable(managed_path(transaction, "operation.json"), operation)
        self._verify_and_sync(directory, manifest)
        receipt = self._persist_receipt(transaction, template)
        receipt_id, already_present = self._publish_receipt(receipt,
            f"/v1/jobs/{template.job_id}/units/{template.work_unit_id}/custody")
        return CustodyReceiveResult(receipt, receipt_id, directory, already_present)

    def attest_scientific_existing(self, *, job: dict, acceptance_id: str,
                                   acceptance: ScientificExportAcceptance | dict,
                                   directory: str | Path, idempotency_key: str, verified_by: str,
                                   adapter_id: str, adapter_version: str, adapter_build_sha256: str,
                                   target_kind: Literal["origin_dataset", "independent_archive"],
                                   restore_ref: str) -> ScientificCustodyResult:
        """Attest the acceptance's durable export inventory, including supplements.

        This never substitutes a subset receipt for original Unit custody and
        never requires a retired MPH. The registered acceptance and strict ACK
        bind the inventory to its original producer at the control plane.
        """
        acceptance = ScientificExportAcceptance.model_validate(acceptance)
        identifier(acceptance_id)
        if acceptance_id != "science-" + sha256_value(acceptance.idempotency_key)[:32]:
            raise LifecycleError("custody_scientific_acceptance_mismatch")
        # Reuse original Job/producer validation without pretending the science
        # inventory is the complete original manifest.
        job_id, unit_id = identifier(job["job_id"]), acceptance.work_unit_id
        units = [u for u in job.get("work_units", []) if u.get("work_unit_id") == unit_id]
        if len(units) != 1:
            raise LifecycleError("custody_unit_not_in_job")
        attempts = [a for a in units[0].get("attempts", [])
                    if a.get("attempt_id") == acceptance.producer_attempt_id]
        if (acceptance.job_id != job_id or acceptance.project_id != job["project_id"]
            or acceptance.request_hash != job["request_hash"] or len(attempts) != 1
            or attempts[0].get("state") != "completed" or not attempts[0].get("collected_at")
            or attempts[0].get("external_run_id") != acceptance.producer_external_id):
            raise LifecycleError("custody_original_producer_mismatch")
        if job.get("origin_adapter_id", "workbench") != adapter_id or acceptance.adapter_id != adapter_id:
            raise LifecycleError("custody_adapter_binding_mismatch")
        template = ScientificCustodyReceipt(idempotency_key=idempotency_key, acceptance_id=acceptance_id,
            scientific_inventory_sha256=acceptance.scientific_inventory_sha256, files=acceptance.scientific_files,
            target=self.destination.location, target_kind=target_kind, verified_by=verified_by,
            adapter_id=adapter_id, adapter_version=adapter_version, adapter_build_sha256=adapter_build_sha256,
            verified_at=datetime.now(timezone.utc), verification_method="sha256_full_read",
            actual_bytes_verified=True, durable_publication=True, restore_ref=restore_ref)
        directory = self._existing_directory(directory)
        root = self.destination.check()
        # Different receipt types cannot collide with legacy Unit operations.
        transaction = managed_path(root, ".scientific-custody-transactions", sha256_value(idempotency_key))
        operation = {"receipt_contract": self._receipt_contract(template),
            "acceptance_sha256": sha256_value(acceptance.model_dump(mode="json")),
            "origin_submitter_id": identifier(job["origin_submitter_id"]),
            "job_id": job_id, "work_unit_id": unit_id,
            "producer_attempt_id": acceptance.producer_attempt_id,
            "directory": directory.relative_to(root).as_posix()}
        self._write_immutable(managed_path(transaction, "operation.json"), operation)
        self._verify_files_and_sync(directory, acceptance.scientific_files)
        receipt = self._persist_receipt(transaction, template)
        receipt_id, already_present = self._publish_receipt(receipt,
            f"/v1/jobs/{job_id}/units/{unit_id}/scientific-custody", prefix="science-custody-",
            id_field="record_id", payload_field="payload")
        return ScientificCustodyResult(receipt, receipt_id, directory, already_present)
