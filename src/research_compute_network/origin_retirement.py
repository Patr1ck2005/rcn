"""Exact source-side retirement coordinated by the original metadata ledger.

RCN authorizes metadata only; a registered origin adapter performs the local
syscall and reports it. Remote process permits survive disconnects, and only
an authenticated exact-process-exit assertion can reconcile a stuck permit.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .hashing import sha256_value
from .models import FileRecord
from .origin_transfer import identifier, managed_path, portable_parts
from .storage_lifecycle import CustodyLocation, LifecycleError, UnitCustodyReceipt, _now, inventory_payload


class OriginRetirementSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_kind: Literal["solved_model_origin", "solved_model_worker", "origin_duplicate", "derived_dependency_input"]
    idempotency_key: str
    job_id: str
    work_unit_id: str
    producer_attempt_id: str
    target: CustodyLocation
    directory_relative_path: str
    scientific_directory_relative_path: str | None = Field(default=None, exclude_if=lambda value: value is None)
    scientific_target: CustodyLocation | None = Field(default=None, exclude_if=lambda value: value is None)
    source_custody_receipt_id: str | None = Field(default=None, exclude_if=lambda value: value is None)
    acceptance_id: str | None = None
    derived_input_id: str | None = Field(default=None, exclude_if=lambda value: value is None)
    formal_receipt_id: str | None = None
    formal_directory_relative_path: str | None = None

    @field_validator("directory_relative_path", "scientific_directory_relative_path", "formal_directory_relative_path")
    @classmethod
    def directory(cls, value):
        if value is not None:
            portable_parts(value)
        return value

    @field_validator("idempotency_key", "job_id", "work_unit_id", "producer_attempt_id")
    @classmethod
    def identity(cls, value):
        return identifier(value)

    @model_validator(mode="after")
    def separate_scientific_source(self):
        if self.scientific_target is None and self.source_custody_receipt_id is None:
            return self
        if (self.operation_kind != "solved_model_origin" or self.scientific_target is None
            or not self.source_custody_receipt_id or not self.scientific_directory_relative_path
            or self.scientific_target == self.target
            or self.scientific_target.host_id != self.target.host_id):
            raise ValueError("cross-root model retirement requires separate local scientific target and source custody")
        identifier(self.source_custody_receipt_id)
        return self


class OriginProcess(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host_id: str
    process_id: int = Field(ge=1, strict=True)
    process_started: float = Field(gt=0)


class OriginFileAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file: FileRecord
    source_identity: list[int] = Field(min_length=5, max_length=5)
    process: OriginProcess
    actual_sha256_verified: Literal[True]
    target_binding_verified: Literal[True]
    formal_copy_verified: Literal[True]


class OriginFileCompletion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    relative_path: str
    owner_token: str
    process: OriginProcess
    result: Literal["deleted", "already_absent"]
    target_binding_verified: Literal[True]


class OriginPermitRecovery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    relative_path: str
    owner_token: str
    previous_process: OriginProcess
    exact_process_exited: Literal[True]


class OriginReaderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: str = Field(min_length=1, max_length=192)
    producer_attempt_id: str
    target: CustodyLocation
    directory_relative_path: str
    relative_path: str
    process: OriginProcess

    @field_validator("directory_relative_path", "relative_path")
    @classmethod
    def path(cls, value):
        portable_parts(value)
        return value


class OriginReaderRelease(BaseModel):
    model_config = ConfigDict(extra="forbid")
    process: OriginProcess
    exact_process_exited: bool = False


class OriginFileAbort(BaseModel):
    model_config = ConfigDict(extra="forbid")
    relative_path: str
    owner_token: str
    process: OriginProcess
    reason: str = Field(min_length=1, max_length=2000)


class OriginRetirement:
    def __init__(self, lifecycle):
        self.life = lifecycle

    def _owner(self, job_id, unit_id, attempt_id, actor_id):
        job, manifest, attempt = self.life._binding(job_id, unit_id, attempt_id)
        grant = self.life.repository.get_project_grant(job.project_id)
        actors = {job.user_id}
        if grant:
            actors.update({grant.owner_user_id, *grant.authorized_user_ids})
        if actor_id not in actors:
            raise LifecycleError("authenticated_adapter_actor_mismatch")
        return job, manifest, attempt

    def _duplicate_evidence(self, db, request, job, manifest, attempt):
        row = db.execute("SELECT * FROM storage_lifecycle_receipts WHERE receipt_id=?", (request.formal_receipt_id,)).fetchone()
        if row is None or row["revoked_at"] is not None:
            raise LifecycleError("formal_custody_missing_or_revoked")
        receipt = UnitCustodyReceipt.model_validate_json(row["payload"])
        if not self.life._matches(receipt, job, manifest, attempt) or receipt.target_kind != "origin_dataset":
            raise LifecycleError("formal_custody_binding_mismatch")
        if receipt.target != request.target:
            raise LifecycleError("origin_target_binding_mismatch")
        if (not request.formal_directory_relative_path or
            request.formal_directory_relative_path.casefold() == request.directory_relative_path.casefold()):
            raise LifecycleError("duplicate_directories_must_differ")
        protected = {"artifact-manifest.json", "manifest.json", "request.json", "provenance.json"}
        files = [f for f in manifest.files if Path(f.relative_path).name.casefold() not in protected
                 and not f.relative_path.casefold().endswith((".log", ".manifest.json", ".provenance.json"))]
        if not files:
            raise LifecycleError("no_retirable_files")
        return files

    def _origin_scientific_source(self, db, request, job, manifest, attempt, proof, copies):
        """Bind model bytes independently of their retained scientific exports."""
        science_target = request.scientific_target or request.target
        if (proof.temporary_model_storage != "center_manifest"
            or not any(copy.target == science_target for copy in copies.values())):
            raise LifecycleError("origin_target_binding_mismatch")
        if request.scientific_target is None:
            return
        row = db.execute("SELECT * FROM storage_lifecycle_receipts WHERE receipt_id=?",
                         (request.source_custody_receipt_id,)).fetchone()
        if row is None or row["revoked_at"] is not None:
            raise LifecycleError("origin_source_custody_missing_or_revoked")
        receipt = UnitCustodyReceipt.model_validate_json(row["payload"])
        if (not self.life._matches(receipt, job, manifest, attempt)
            or receipt.target_kind != "origin_dataset" or receipt.target != request.target):
            raise LifecycleError("origin_source_custody_binding_mismatch")

    def worker_location(self, machine_id):
        config = self.life.repository.get_machine_execution_config(machine_id)
        if config is None or not config.root_uuid:
            raise LifecycleError("worker_root_unregistered")
        return CustodyLocation(host_id=machine_id, store_id="worker-recovery", volume_id=config.remote_root,
            generation=config.root_uuid, physical_device_id="worker-root:" + machine_id + ":" + config.root_uuid)

    def _worker_binding(self, request, job, attempt, proof):
        if not attempt.machine_id or proof.temporary_model_storage != "worker_recovery":
            raise LifecycleError("worker_recovery_binding_required")
        if request.target != self.worker_location(attempt.machine_id):
            raise LifecycleError("worker_root_binding_mismatch")
        if not self.life.repository.get_machine_execution_config(attempt.machine_id).scientific_model_retirement_enabled:
            raise LifecycleError("worker_model_retirement_disabled")
        expected = "/".join(("runs", "retained", "success", job.project_id, job.job_id, request.work_unit_id))
        if request.directory_relative_path != expected:
            raise LifecycleError("worker_run_binding_mismatch")
        run = self.life.repository.get_remote_run(attempt.external_run_id)
        if run is None or (run.machine_id, run.job_id, run.work_unit_id) != (attempt.machine_id, job.job_id, request.work_unit_id):
            raise LifecycleError("worker_request_binding_missing")
        return run

    def _source_history(self, db, payload, *, inspect_pending=True):
        """Original permits/retirements belong to exact physical source bytes.

        A superseded proof may leave an unstarted intent. It must not reserve
        remaining files forever, but an unacknowledged syscall always does.
        Completed history is retained and never rewritten into a new intent.
        """
        own_id = "origin-retire-" + sha256_value(payload["idempotency_key"])[:32]
        wanted = {f["relative_path"].casefold(): f for f in payload["files"]}
        retired = {}
        for row in db.execute("SELECT intent_id,payload FROM storage_lifecycle_intents "
            "WHERE json_extract(payload,'$.target.host_id')=? AND json_extract(payload,'$.target.store_id')=? "
            "AND json_extract(payload,'$.directory_relative_path')=? COLLATE NOCASE",
            (payload["target"]["host_id"], payload["target"]["store_id"], payload["directory_relative_path"])).fetchall():
            if row["intent_id"] == own_id:
                continue
            prior = json.loads(row["payload"])
            if (prior.get("operation_kind") not in {"solved_model_origin", "solved_model_worker", "origin_duplicate", "derived_dependency_input"}
                or prior.get("target") != payload["target"]
                or prior["directory_relative_path"].casefold() != payload["directory_relative_path"].casefold()):
                continue
            overlap = [f for f in prior["files"] if wanted.get(f["relative_path"].casefold()) == f]
            if not overlap:
                continue
            states = {r["relative_path"]: r["state"] for r in db.execute(
                "SELECT relative_path,state FROM storage_lifecycle_deletions WHERE intent_id=?", (row["intent_id"],))}
            for file in overlap:
                if db.execute("SELECT 1 FROM storage_lifecycle_writer_permits WHERE intent_id=? AND relative_path=?",
                              (row["intent_id"], file["relative_path"])).fetchone():
                    raise LifecycleError("file_retirement_in_progress")
                if states.get(file["relative_path"]) in {"deleted", "already_absent"}:
                    retired.setdefault(file["relative_path"].casefold(), {"intent_id": row["intent_id"], "file": file})
                elif inspect_pending:
                    try:
                        self.check(db, prior, actor_id=prior["authorized_actor"], inspect_history=False)
                    except LifecycleError:
                        # Fresh evidence for the new request is checked below.
                        # An old invalid proof with no permit has no syscall.
                        pass
                    else:
                        raise LifecycleError("origin_retirement_already_has_original_key")
        return [retired[key] for key in sorted(retired)]

    def create(self, request: OriginRetirementSelection, *, actor_id):
        request = OriginRetirementSelection.model_validate(request)
        job, manifest, attempt = self._owner(request.job_id, request.work_unit_id, request.producer_attempt_id, actor_id)
        operation = request.model_dump(mode="json")
        fingerprint = sha256_value(operation)
        life = self.life
        with life._connect() as db:
            old = db.execute("SELECT * FROM storage_lifecycle_intents WHERE idempotency_key=?", (request.idempotency_key,)).fetchone()
            if old:
                if old["fingerprint"] != fingerprint:
                    raise LifecycleError("idempotency_key_conflict")
                return life.get_intent(old["intent_id"])
            if request.operation_kind in {"solved_model_origin", "solved_model_worker"}:
                if not request.acceptance_id:
                    raise LifecycleError("scientific_acceptance_required")
                proof, _, _, _, policy, copies, expires, files = life.scientific._evidence(db, request.acceptance_id)
                if (proof.job_id, proof.work_unit_id, proof.producer_attempt_id) != (request.job_id, request.work_unit_id, request.producer_attempt_id):
                    raise LifecycleError("scientific_producer_binding_mismatch")
                if request.operation_kind == "solved_model_worker":
                    worker_run = self._worker_binding(request, job, attempt, proof)
                else:
                    self._origin_scientific_source(db, request, job, manifest, attempt, proof, copies)
                extra = {"receipt_ids": sorted(copies), "model_policy_sha256": sha256_value(policy.model_dump(mode="json")),
                         "expires_at": expires.isoformat()}
                if request.operation_kind == "solved_model_worker":
                    extra.update(request_hash=worker_run.request_hash, job_request_hash=job.request_hash,
                        root_uuid=request.target.generation, producer_external_id=attempt.external_run_id,
                        temporary_inventory_file=proof.temporary_inventory_file.model_dump(mode="json"),
                        original_files=inventory_payload(manifest.files))
            elif request.operation_kind == "derived_dependency_input":
                files, extra = life.derived_inputs.evidence(db, request, actor_id=actor_id)
            else:
                files = self._duplicate_evidence(db, request, job, manifest, attempt)
                extra = {}
        if request.operation_kind == "origin_duplicate":
            # The incoming inventory is the second retained device
            # for this initial duplicate-only path. No center-copy GC is issued.
            if life.center_binding is None or life.center_binding.physical_key() == request.target.physical_key():
                raise LifecycleError("scientific_independent_copies_missing")
            directory = life._directory(job, request.work_unit_id, request.producer_attempt_id)
            for record in manifest.files:
                life._verify_source(managed_path(directory, record.relative_path), record.model_dump(mode="json"))
        intent_id = "origin-retire-" + sha256_value(request.idempotency_key)[:32]
        payload = {**operation, **extra, "original_manifest": manifest.model_dump(mode="json"),
            "manifest_sha256": sha256_value(manifest.model_dump(mode="json")), "files": inventory_payload(files),
            "center_binding": life.center_binding.model_dump(mode="json") if life.center_binding else None,
            "authorized_actor": actor_id}
        with life._transaction() as db:
            if request.operation_kind != "origin_duplicate":
                retired = self._source_history(db, payload)
                payload["eligible_files"] = payload["files"]
                payload["prior_retired_files"] = retired
                gone = {entry["file"]["relative_path"].casefold() for entry in retired}
                files = [f for f in files if f.relative_path.casefold() not in gone]
                if not files:
                    raise LifecycleError("all_source_files_already_retired")
                payload["files"] = inventory_payload(files)
            # New scientific subsets have distinct identity. Existing kinds,
            # immutable payloads and their historical syscall records stay intact.
            scope = {"target": operation["target"], "directory": request.directory_relative_path}
            if request.operation_kind != "origin_duplicate":
                scope.update(acceptance_id=request.acceptance_id, derived_input_id=request.derived_input_id,
                             files=payload["files"])
            kind = request.operation_kind + ":" + sha256_value(scope)[:24]
            self.check(db, payload, actor_id=actor_id)
            old = db.execute("SELECT * FROM storage_lifecycle_intents WHERE idempotency_key=?", (request.idempotency_key,)).fetchone()
            if old:
                if old["fingerprint"] != fingerprint:
                    raise LifecycleError("idempotency_key_conflict")
                return life.get_intent(old["intent_id"])
            prior = db.execute("SELECT 1 FROM storage_lifecycle_intents WHERE job_id=? AND unit_id=? AND attempt_id=? AND operation_kind=?",
                               (request.job_id, request.work_unit_id, request.producer_attempt_id, kind)).fetchone()
            if prior:
                raise LifecycleError("origin_retirement_already_has_original_key")
            db.execute("INSERT INTO storage_lifecycle_intents "
                "(intent_id,idempotency_key,job_id,unit_id,attempt_id,fingerprint,payload,state,created_at,operation_kind) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (intent_id, request.idempotency_key, request.job_id, request.work_unit_id, request.producer_attempt_id,
                 fingerprint, life._json(payload), "pending", _now(), kind))
            for file in files:
                db.execute("INSERT INTO storage_lifecycle_deletions VALUES(?,?,?,?)", (intent_id, file.relative_path, "pending", _now()))
            life._audit(db, "storage.origin_retirement_committed", actor_id, intent_id,
                        target=operation["target"], directory_relative_path=request.directory_relative_path, files=payload["files"])
        return life.get_intent(intent_id)

    def check(self, db, payload, *, actor_id, inspect_history=True):
        life = self.life
        job, manifest, attempt = self._owner(payload["job_id"], payload["work_unit_id"], payload["producer_attempt_id"], actor_id)
        if payload["authorized_actor"] != actor_id or sha256_value(manifest.model_dump(mode="json")) != payload["manifest_sha256"]:
            raise LifecycleError("origin_retirement_binding_changed")
        if life.center_binding is None or payload["center_binding"] != life.center_binding.model_dump(mode="json"):
            raise LifecycleError("retirement_binding_changed")
        request = OriginRetirementSelection.model_validate({k: payload[k] for k in OriginRetirementSelection.model_fields if k in payload})
        if request.operation_kind in {"solved_model_origin", "solved_model_worker"}:
            proof, _, _, _, policy, copies, expires, files = life.scientific._evidence(db, payload["acceptance_id"], receipt_ids=payload["receipt_ids"])
            if not life.scientific.retirement_policy_matches(payload, expires, files):
                raise LifecycleError("model_retirement_policy_changed")
            if request.operation_kind == "solved_model_worker":
                worker_run = self._worker_binding(request, job, attempt, proof)
                if payload["request_hash"] != worker_run.request_hash or payload["job_request_hash"] != job.request_hash:
                    raise LifecycleError("worker_request_binding_changed")
            else:
                self._origin_scientific_source(db, request, job, manifest, attempt, proof, copies)
        elif request.operation_kind == "derived_dependency_input":
            files, _ = life.derived_inputs.evidence(db, request, actor_id=actor_id, frozen=payload)
            if inventory_payload(files) != payload.get("eligible_files", payload["files"]):
                raise LifecycleError("derived_input_retirement_evidence_changed")
        else:
            files = self._duplicate_evidence(db, request, job, manifest, attempt)
            if inventory_payload(files) != payload["files"]:
                raise LifecycleError("origin_retirement_binding_changed")
        if inspect_history and request.operation_kind != "origin_duplicate":
            logical = {**payload, "files": payload.get("eligible_files", payload["files"])}
            prior_retired = self._source_history(db, logical)
            if prior_retired != payload.get("prior_retired_files", []):
                raise LifecycleError("origin_source_retirement_history_changed")
            gone = {entry["file"]["relative_path"].casefold() for entry in prior_retired}
            expected = [file for file in logical["files"] if file["relative_path"].casefold() not in gone]
            if expected != payload["files"]:
                raise LifecycleError("origin_source_retirement_history_changed")
        for permit in db.execute("SELECT p.* FROM storage_lifecycle_writer_permits p JOIN storage_lifecycle_intents i "
                "ON i.intent_id=p.intent_id WHERE i.job_id=? AND i.unit_id=? AND i.attempt_id=? "
                "AND i.operation_kind IN ('relay_copy','solved_model')",
                (request.job_id, request.work_unit_id, request.producer_attempt_id)).fetchall():
            if not life._reconcile_dead_writer(db, permit):
                raise LifecycleError("file_retirement_in_progress")
        if db.execute("SELECT 1 FROM storage_lifecycle_readers WHERE job_id=? AND unit_id=? AND attempt_id=?",
                      (request.job_id, request.work_unit_id, request.producer_attempt_id)).fetchone():
            raise LifecycleError("live_readers")
        return request

    def get(self, intent_id, *, actor_id):
        intent = self.life.get_intent(intent_id)
        payload = intent["candidate"]
        if payload.get("operation_kind") not in {"solved_model_origin", "solved_model_worker", "origin_duplicate", "derived_dependency_input"}:
            raise LifecycleError("origin_intent_required")
        self._owner(payload["job_id"], payload["work_unit_id"], payload["producer_attempt_id"], actor_id)
        if payload["authorized_actor"] != actor_id:
            raise LifecycleError("authenticated_adapter_actor_mismatch")
        with self.life._connect() as db:
            intent["writer_permits"] = {row["relative_path"]: {"owner_token": row["owner_token"],
                "process": {"host_id": row["process_host"].removeprefix("origin:"),
                            "process_id": row["process_id"], "process_started": row["process_started"]}}
                for row in db.execute("SELECT * FROM storage_lifecycle_writer_permits WHERE intent_id=?", (intent_id,))}
        return intent

    def pin_reader(self, job_id, unit_id, request: OriginReaderRequest, *, actor_id):
        job, manifest, attempt = self._owner(job_id, unit_id, request.producer_attempt_id, actor_id)
        if request.process.host_id != request.target.host_id:
            raise LifecycleError("origin_process_host_mismatch")
        life = self.life
        pin_id = "origin-reader-" + sha256_value(request.idempotency_key)[:32]
        with life._transaction() as db:
            prior = db.execute("SELECT details FROM storage_lifecycle_audit WHERE subject_id=? "
                               "AND event_type='storage.origin_reader_pinned' ORDER BY sequence DESC LIMIT 1", (pin_id,)).fetchone()
            fingerprint = sha256_value({"job_id": job_id, "unit_id": unit_id, "actor_id": actor_id,
                                        "request": request.model_dump(mode="json")})
            if prior is not None:
                if json.loads(prior[0])["fingerprint"] != fingerprint:
                    raise LifecycleError("idempotency_key_conflict")
                if not db.execute("SELECT 1 FROM storage_lifecycle_readers WHERE pin_id=?", (pin_id,)).fetchone():
                    raise LifecycleError("origin_reader_key_already_released")
                return {"pin_id": pin_id, "process": request.process.model_dump(mode="json")}
            science = db.execute("SELECT payload FROM scientific_export_acceptances WHERE job_id=? AND unit_id=? AND attempt_id=?",
                                 (job_id, unit_id, attempt.attempt_id)).fetchall()
            names = {f.relative_path for f in manifest.files}
            for proof in science:
                names.update(f["relative_path"] for f in json.loads(proof[0])["scientific_files"])
            for row in db.execute("SELECT payload FROM scientific_derived_inputs WHERE job_id=? AND unit_id=? AND attempt_id=? AND revoked_at IS NULL",
                                  (job_id, unit_id, attempt.attempt_id)):
                derived = json.loads(row[0])
                if (derived["target"] == request.target.model_dump(mode="json") and
                    derived["directory_relative_path"] == request.directory_relative_path):
                    names.add(derived["derived_input_file"]["relative_path"])
            if request.relative_path not in names:
                raise LifecycleError("file_not_in_manifest")
            for row in db.execute("SELECT intent_id,payload FROM storage_lifecycle_intents WHERE job_id=? AND unit_id=? AND attempt_id=?",
                                  (job_id, unit_id, attempt.attempt_id)).fetchall():
                payload = json.loads(row["payload"])
                if payload.get("operation_kind") not in {"solved_model_origin", "origin_duplicate", "derived_dependency_input"}:
                    continue
                if payload["target"] != request.target.model_dump(mode="json") or payload["directory_relative_path"] != request.directory_relative_path:
                    continue
                if request.relative_path not in {f["relative_path"] for f in payload["files"]}:
                    continue
                if db.execute("SELECT 1 FROM storage_lifecycle_writer_permits WHERE intent_id=? AND relative_path=?",
                              (row["intent_id"], request.relative_path)).fetchone():
                    raise LifecycleError("file_retirement_in_progress")
                try:
                    self.check(db, payload, actor_id=actor_id)
                except LifecycleError as exc:
                    if exc.reason_code == "live_readers":
                        raise LifecycleError("result_retirement_pending_or_completed") from exc
                    # Invalidated custody or new user exception permits recovery
                    # inspection of any remaining exact source file.
                else:
                    raise LifecycleError("result_retirement_pending_or_completed")
            db.execute("INSERT INTO storage_lifecycle_readers VALUES(?,?,?,?,?,?,?,?,?)",
                       (pin_id, job_id, unit_id, attempt.attempt_id, request.relative_path,
                        "origin:" + request.process.host_id, request.process.process_id,
                        request.process.process_started, _now()))
            life._audit(db, "storage.origin_reader_pinned", actor_id, pin_id,
                        target=request.target.model_dump(mode="json"), directory_relative_path=request.directory_relative_path,
                        fingerprint=fingerprint)
        return {"pin_id": pin_id, "process": request.process.model_dump(mode="json")}

    def release_reader(self, job_id, unit_id, pin_id, request: OriginReaderRelease, *, actor_id):
        life = self.life
        with life._transaction() as db:
            row = db.execute("SELECT * FROM storage_lifecycle_readers WHERE pin_id=?", (pin_id,)).fetchone()
            if row is None:
                return {"released": False}
            self._owner(job_id, unit_id, row["attempt_id"], actor_id)
            if (row["job_id"], row["unit_id"], row["process_host"], row["process_id"], row["process_started"]) != (
                job_id, unit_id, "origin:" + request.process.host_id, request.process.process_id, request.process.process_started):
                raise LifecycleError("origin_reader_binding_mismatch")
            db.execute("DELETE FROM storage_lifecycle_readers WHERE pin_id=?", (pin_id,))
            life._audit(db, "storage.origin_reader_released", actor_id, pin_id,
                        exact_process_exited=request.exact_process_exited)
        return {"released": True}

    def abort(self, intent_id, request: OriginFileAbort, *, actor_id):
        life = self.life
        self.get(intent_id, actor_id=actor_id)
        with life._transaction() as db:
            permit = db.execute("SELECT * FROM storage_lifecycle_writer_permits WHERE intent_id=? AND relative_path=?",
                                (intent_id, request.relative_path)).fetchone()
            if permit is None:
                return {"aborted": False}
            if (permit["owner_token"], permit["process_host"], permit["process_id"], permit["process_started"]) != (
                request.owner_token, "origin:" + request.process.host_id, request.process.process_id, request.process.process_started):
                raise LifecycleError("origin_file_authorization_mismatch")
            db.execute("DELETE FROM storage_lifecycle_writer_permits WHERE intent_id=? AND relative_path=? AND owner_token=?",
                       (intent_id, request.relative_path, request.owner_token))
            life._audit(db, "storage.origin_file_authorization_aborted", actor_id, intent_id,
                        relative_path=request.relative_path, owner_token=request.owner_token, reason=request.reason)
        return {"aborted": True}

    def authorize(self, intent_id, request: OriginFileAuthorization, *, actor_id):
        life = self.life
        intent = self.get(intent_id, actor_id=actor_id)
        payload = intent["candidate"]
        record = next((f for f in payload["files"] if f["relative_path"] == request.file.relative_path), None)
        if record is None or record != inventory_payload([request.file])[0]:
            raise LifecycleError("file_not_in_origin_intent")
        if request.process.host_id != payload["target"]["host_id"]:
            raise LifecycleError("origin_process_host_mismatch")
        with life._transaction() as db:
            self.check(db, payload, actor_id=actor_id)
            saved = db.execute("SELECT state FROM storage_lifecycle_deletions WHERE intent_id=? AND relative_path=?",
                               (intent_id, request.file.relative_path)).fetchone()[0]
            if saved != "pending":
                return {"state": saved, "intent_id": intent_id, "relative_path": request.file.relative_path}
            existing = db.execute("SELECT * FROM storage_lifecycle_writer_permits WHERE intent_id=? AND relative_path=?",
                                  (intent_id, request.file.relative_path)).fetchone()
            if existing is not None:
                if (existing["process_host"], existing["process_id"], existing["process_started"]) != (
                    "origin:" + request.process.host_id, request.process.process_id, request.process.process_started):
                    raise LifecycleError("file_retirement_in_progress")
                return {"state": "authorized", "intent_id": intent_id, "relative_path": request.file.relative_path,
                        "owner_token": existing["owner_token"], "process": request.process.model_dump(mode="json")}
            token = life._claim_writer_permit(db, intent_id, request.file.relative_path)
            db.execute("UPDATE storage_lifecycle_writer_permits SET process_host=?,process_id=?,process_started=? "
                       "WHERE intent_id=? AND relative_path=? AND owner_token=?",
                       ("origin:" + request.process.host_id, request.process.process_id, request.process.process_started,
                        intent_id, request.file.relative_path, token))
            life._audit(db, "storage.origin_file_authorized", actor_id, intent_id,
                        relative_path=request.file.relative_path, source_identity=request.source_identity,
                        process=request.process.model_dump(mode="json"), target=payload["target"])
        return {"state": "authorized", "intent_id": intent_id, "relative_path": request.file.relative_path,
                "owner_token": token, "process": request.process.model_dump(mode="json")}

    def complete(self, intent_id, request: OriginFileCompletion, *, actor_id):
        life = self.life
        intent = self.get(intent_id, actor_id=actor_id)
        with life._transaction() as db:
            existing = db.execute("SELECT state FROM storage_lifecycle_deletions WHERE intent_id=? AND relative_path=?",
                                  (intent_id, request.relative_path)).fetchone()
            if existing is None:
                raise LifecycleError("file_not_in_origin_intent")
            if existing[0] != "pending":
                if existing[0] != request.result:
                    raise LifecycleError("origin_completion_changed")
                return life.get_intent(intent_id)
            permit = db.execute("SELECT * FROM storage_lifecycle_writer_permits WHERE intent_id=? AND relative_path=?",
                                (intent_id, request.relative_path)).fetchone()
            if permit is None or (permit["owner_token"], permit["process_host"], permit["process_id"], permit["process_started"]) != (
                request.owner_token, "origin:" + request.process.host_id, request.process.process_id, request.process.process_started):
                raise LifecycleError("origin_file_authorization_mismatch")
            db.execute("UPDATE storage_lifecycle_deletions SET state=?,updated_at=? WHERE intent_id=? AND relative_path=?",
                       (request.result, _now(), intent_id, request.relative_path))
            db.execute("DELETE FROM storage_lifecycle_writer_permits WHERE intent_id=? AND relative_path=? AND owner_token=?",
                       (intent_id, request.relative_path, request.owner_token))
            pending = db.execute("SELECT 1 FROM storage_lifecycle_deletions WHERE intent_id=? AND state='pending' LIMIT 1", (intent_id,)).fetchone()
            db.execute("UPDATE storage_lifecycle_intents SET state=?,completed_at=? WHERE intent_id=?",
                       ("pending" if pending else "completed", None if pending else _now(), intent_id))
            life._audit(db, "storage.origin_file_retired", actor_id, intent_id,
                        relative_path=request.relative_path, result=request.result, target=intent["candidate"]["target"])
        return life.get_intent(intent_id)

    def reconcile(self, intent_id, request: OriginPermitRecovery, *, actor_id):
        life = self.life
        self.get(intent_id, actor_id=actor_id)
        with life._transaction() as db:
            permit = db.execute("SELECT * FROM storage_lifecycle_writer_permits WHERE intent_id=? AND relative_path=?",
                                (intent_id, request.relative_path)).fetchone()
            if permit is None:
                return {"reconciled": False, "reason_code": "permit_already_released"}
            if (permit["owner_token"], permit["process_host"], permit["process_id"], permit["process_started"]) != (
                request.owner_token, "origin:" + request.previous_process.host_id,
                request.previous_process.process_id, request.previous_process.process_started):
                raise LifecycleError("origin_file_authorization_mismatch")
            db.execute("DELETE FROM storage_lifecycle_writer_permits WHERE intent_id=? AND relative_path=? AND owner_token=?",
                       (intent_id, request.relative_path, request.owner_token))
            life._audit(db, "storage.origin_writer_exit_asserted", actor_id, intent_id,
                        relative_path=request.relative_path, evidence_kind="authenticated_origin_exact_process_exit",
                        previous_process=request.previous_process.model_dump(mode="json"))
        return {"reconciled": True}
