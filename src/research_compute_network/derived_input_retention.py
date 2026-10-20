"""Explicit temporary derived inputs, separate from baseline/output inventories.

Only the authenticated scientific adapter can attest a materialization. The
ledger verifies its original producers and durable scientific evidence; source
syscalls continue to use the existing origin permit and recovery protocol.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .hashing import sha256_value
from .models import FileRecord
from .origin_transfer import identifier, portable_parts
from .scientific_retention import ScientificCustodyReceipt, _aware
from .storage_lifecycle import CustodyLocation, LifecycleError, inventory_payload, _now


class DerivedInputRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    role: Literal["temporary_dependency_input"]
    idempotency_key: str
    project_id: str
    job_id: str
    work_unit_id: str
    producer_attempt_id: str
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    consumer_acceptance_id: str
    parent_acceptance_id: str
    parent_model_file: FileRecord
    parent_original_baseline_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    derived_input_file: FileRecord
    materialization_evidence_files: list[FileRecord] = Field(min_length=1, max_length=256)
    materialization_analysis_id: str = Field(min_length=1, max_length=192)
    materialized_at: datetime
    actual_materialization_verified: Literal[True]
    input_sha256_verified: Literal[True]
    input_durable_publication: Literal[True]
    target: CustodyLocation
    directory_relative_path: str
    scientific_directory_relative_path: str
    verified_by: str
    adapter_id: str
    adapter_version: str = Field(min_length=1)
    adapter_build_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    _time = field_validator("materialized_at")(_aware)

    @field_validator("idempotency_key", "project_id", "job_id", "work_unit_id", "producer_attempt_id",
                     "consumer_acceptance_id", "parent_acceptance_id", "verified_by", "adapter_id")
    @classmethod
    def ids(cls, value):
        return identifier(value)

    @field_validator("directory_relative_path", "scientific_directory_relative_path")
    @classmethod
    def directory(cls, value):
        portable_parts(value)
        return value

    @field_validator("derived_input_file", "parent_model_file")
    @classmethod
    def model(cls, file):
        inventory_payload([file])
        if Path(file.relative_path).suffix.casefold() != ".mph":
            raise ValueError("a temporary dependency input must identify an exact MPH")
        return file

    @field_validator("materialization_evidence_files")
    @classmethod
    def evidence(cls, files):
        inventory_payload(files)
        if any(Path(f.relative_path).suffix.casefold() == ".mph" for f in files):
            raise ValueError("materialization evidence must be durable scientific exports")
        return files


class DerivedInputRetention:
    def __init__(self, lifecycle):
        self.life = lifecycle
        with lifecycle._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS scientific_derived_inputs (
                  record_id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE NOT NULL,
                  job_id TEXT NOT NULL, unit_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
                  fingerprint TEXT NOT NULL, payload TEXT NOT NULL, recorded_at TEXT NOT NULL,
                  revoked_at TEXT, revoke_reason TEXT);
                CREATE INDEX IF NOT EXISTS scientific_derived_input_unit
                  ON scientific_derived_inputs(job_id,unit_id,attempt_id);
            """)

    def _binding(self, request, actor_id):
        science = self.life.scientific
        consumer = science.get_acceptance(request.consumer_acceptance_id)
        authorized = consumer.model_copy(update={k: getattr(request, k) for k in
            ("verified_by", "adapter_id", "adapter_version", "adapter_build_sha256")})
        job, manifest, attempt = science._authorize(authorized, actor_id, recorded=True)
        if (request.project_id, request.job_id, request.work_unit_id, request.producer_attempt_id,
            request.request_hash, request.manifest_sha256) != (
            consumer.project_id, consumer.job_id, consumer.work_unit_id, consumer.producer_attempt_id,
            consumer.request_hash, consumer.manifest_sha256):
            raise LifecycleError("derived_input_consumer_binding_mismatch")
        parent = science.get_acceptance(request.parent_acceptance_id)
        parent_job, _, _ = science._authorize(parent, parent.verified_by, recorded=True)
        if parent.project_id != request.project_id:
            raise LifecycleError("derived_input_parent_project_mismatch")
        if inventory_payload([request.parent_model_file])[0] not in inventory_payload(parent.temporary_model_files):
            raise LifecycleError("derived_input_parent_model_mismatch")
        if request.parent_original_baseline_sha256 != parent_job.template_sha256:
            raise LifecycleError("derived_input_baseline_binding_mismatch")
        if request.derived_input_file.sha256 in {request.parent_original_baseline_sha256, request.parent_model_file.sha256}:
            raise LifecycleError("source_baseline_protected")
        if request.derived_input_file.sha256 != job.template_sha256:
            raise LifecycleError("derived_input_not_consumer_template")
        bound_inputs = [f for f in job.input_manifest if f.sha256 == job.template_sha256]
        if not bound_inputs or any(f.size_bytes != request.derived_input_file.size_bytes for f in bound_inputs):
            raise LifecycleError("derived_input_original_input_mismatch")
        if attempt.state != "completed" or attempt.collected_at is None:
            raise LifecycleError("derived_input_consumer_not_completed_and_collected")
        evidence = inventory_payload(parent.scientific_files)
        if any(f not in evidence for f in inventory_payload(request.materialization_evidence_files)):
            raise LifecycleError("materialization_evidence_not_durable_science")
        if request.materialization_analysis_id not in {a.analysis_id for a in parent.critical_analyses}:
            raise LifecycleError("materialization_analysis_missing")
        model_path = "/".join((request.directory_relative_path, request.derived_input_file.relative_path)).casefold()
        science_paths = {"/".join((request.scientific_directory_relative_path, f.relative_path)).casefold()
                         for f in consumer.scientific_files}
        if model_path in science_paths:
            raise LifecycleError("derived_input_scientific_path_overlap")
        return consumer, parent, job, manifest, attempt

    @staticmethod
    def _copies(db, acceptance_id):
        return {row["receipt_id"]: ScientificCustodyReceipt.model_validate_json(row["payload"])
                for row in db.execute("SELECT * FROM scientific_export_custody WHERE acceptance_id=? AND revoked_at IS NULL",
                                      (acceptance_id,))}

    def _validate(self, db, request, actor_id):
        consumer, parent, job, manifest, attempt = self._binding(request, actor_id)
        for proof in (parent, consumer):
            copies = self._copies(db, request.parent_acceptance_id if proof is parent else request.consumer_acceptance_id)
            if len({c.target.physical_key() for c in copies.values()}) < 2:
                raise LifecycleError("scientific_independent_copies_missing")
            if proof is consumer and not any(c.target == request.target for c in copies.values()):
                raise LifecycleError("origin_target_binding_mismatch")
        return consumer, parent, job, manifest, attempt

    def register(self, request: DerivedInputRegistration, *, actor_id):
        request = DerivedInputRegistration.model_validate(request)
        # New registration uses the currently registered adapter version. Its
        # immutable retry survives a later version upgrade without new evidence.
        payload = request.model_dump(mode="json")
        fingerprint = sha256_value(payload)
        record_id = "derived-input-" + sha256_value(request.idempotency_key)[:32]
        with self.life._transaction() as db:
            old = db.execute("SELECT * FROM scientific_derived_inputs WHERE idempotency_key=?", (request.idempotency_key,)).fetchone()
            if old:
                if old["fingerprint"] != fingerprint:
                    raise LifecycleError("idempotency_key_conflict")
                self.life.origin_retirement._owner(request.job_id, request.work_unit_id, request.producer_attempt_id, actor_id)
                if request.verified_by != actor_id:
                    raise LifecycleError("authenticated_adapter_actor_mismatch")
                return {"record_id": record_id, "payload": json.loads(old["payload"]),
                        "already_present": True, "revoked": old["revoked_at"] is not None}
            adapter = self.life.repository.get_origin_adapter(request.adapter_id)
            if adapter is None or request.adapter_version != adapter.version:
                raise LifecycleError("origin_adapter_binding_mismatch")
            self._validate(db, request, actor_id)
            db.execute("INSERT INTO scientific_derived_inputs "
                "(record_id,idempotency_key,job_id,unit_id,attempt_id,fingerprint,payload,recorded_at) VALUES(?,?,?,?,?,?,?,?)",
                (record_id, request.idempotency_key, request.job_id, request.work_unit_id, request.producer_attempt_id,
                 fingerprint, self.life._json(payload), _now()))
            self.life._audit(db, "storage.derived_dependency_input_registered", actor_id, record_id, fingerprint=fingerprint)
        return {"record_id": record_id, "payload": payload, "already_present": False, "revoked": False}

    def get(self, db, record_id):
        row = db.execute("SELECT * FROM scientific_derived_inputs WHERE record_id=?", (record_id,)).fetchone()
        if row is None or row["revoked_at"] is not None:
            raise LifecycleError("derived_input_missing_or_revoked")
        return DerivedInputRegistration.model_validate_json(row["payload"])

    def state(self, job_id, unit_id, attempt_id, *, actor_id):
        self.life.origin_retirement._owner(job_id, unit_id, attempt_id, actor_id)
        with self.life._connect() as db:
            return {"registrations": [{"record_id": row["record_id"], "payload": json.loads(row["payload"]),
                    "revoked": row["revoked_at"] is not None} for row in db.execute(
                    "SELECT * FROM scientific_derived_inputs WHERE job_id=? AND unit_id=? AND attempt_id=? ORDER BY recorded_at",
                    (job_id, unit_id, attempt_id))]}

    def revoke(self, record_id, *, actor_id, reason):
        if not reason.strip():
            raise LifecycleError("reason_required")
        with self.life._transaction() as db:
            request = self.get(db, record_id)
            self.life.origin_retirement._owner(request.job_id, request.work_unit_id, request.producer_attempt_id, actor_id)
            db.execute("UPDATE scientific_derived_inputs SET revoked_at=?,revoke_reason=? WHERE record_id=?",
                       (_now(), reason, record_id))
            self.life._audit(db, "storage.derived_dependency_input_revoked", actor_id, record_id, reason=reason)

    def evidence(self, db, selection, *, actor_id, frozen=None):
        if not selection.derived_input_id:
            raise LifecycleError("derived_input_registration_required")
        request = self.get(db, selection.derived_input_id)
        if (request.job_id, request.work_unit_id, request.producer_attempt_id, request.target,
            request.directory_relative_path, request.consumer_acceptance_id) != (
            selection.job_id, selection.work_unit_id, selection.producer_attempt_id, selection.target,
            selection.directory_relative_path, selection.acceptance_id):
            raise LifecycleError("derived_input_selection_mismatch")
        if (selection.scientific_directory_relative_path is not None and
            selection.scientific_directory_relative_path != request.scientific_directory_relative_path):
            raise LifecycleError("derived_input_scientific_directory_mismatch")
        _, parent, _, _, _ = self._validate(db, request, actor_id)
        science = self.life.scientific
        proof, _, _, _, policy, copies, expires, _ = science._evidence(db, request.consumer_acceptance_id,
            receipt_ids=frozen.get("receipt_ids") if frozen else None, require_retirable_models=False)
        source_path = "/".join((request.directory_relative_path, request.derived_input_file.relative_path))
        if (science._protected(request.derived_input_file.relative_path, proof, policy) or
            science._protected(source_path, proof, policy)):
            raise LifecycleError("derived_input_user_protected")
        parent_copies = self._copies(db, request.parent_acceptance_id)
        if frozen:
            selected = {key: parent_copies[key] for key in frozen["parent_receipt_ids"] if key in parent_copies}
            if set(selected) != set(frozen["parent_receipt_ids"]):
                raise LifecycleError("scientific_custody_revoked_or_changed")
        else:
            selected, devices = {}, set()
            for key, copy in sorted(parent_copies.items(), key=lambda item: (item[1].verified_at, item[0])):
                if copy.target.physical_key() not in devices:
                    selected[key] = copy
                    devices.add(copy.target.physical_key())
                if len(devices) == 2:
                    break
        historical = any((e.job_id, e.work_unit_id, e.producer_attempt_id) ==
                         (proof.job_id, proof.work_unit_id, proof.producer_attempt_id)
                         for e in policy.historical_cleanup_authorizations)
        materialization_gate = max(request.materialized_at, parent.export_accepted_at,
            *(a.completed_at for a in parent.critical_analyses), *(c.verified_at for c in selected.values()))
        expires = max(expires, materialization_gate + timedelta(hours=0 if historical else policy.grace_hours))
        if datetime.now(timezone.utc) < expires:
            raise LifecycleError("model_grace_period_active")
        # Any other registered Job/Unit using these exact input bytes also
        # requires its completed scientific handoff. Failed/queued consumers
        # remain recoverable until explicitly resolved, rather than guessed away.
        peers = db.execute("SELECT j.job_id,json_extract(u.value,'$.work_unit_id') AS unit_id FROM jobs j, "
            "json_each(j.payload,'$.work_units') u WHERE json_extract(j.payload,'$.template_sha256')=? OR "
            "EXISTS(SELECT 1 FROM json_each(j.payload,'$.input_manifest') f WHERE json_extract(f.value,'$.sha256')=?)",
            (request.derived_input_file.sha256, request.derived_input_file.sha256)).fetchall()
        for peer in peers:
            if (peer["job_id"], peer["unit_id"]) == (proof.job_id, proof.work_unit_id):
                continue
            rows = db.execute("SELECT record_id,payload FROM scientific_derived_inputs WHERE job_id=? AND unit_id=? AND revoked_at IS NULL",
                              (peer["job_id"], peer["unit_id"])).fetchall()
            matched = [DerivedInputRegistration.model_validate_json(row["payload"]) for row in rows]
            matched = [r for r in matched if r.derived_input_file.sha256 == request.derived_input_file.sha256]
            if len(matched) != 1:
                raise LifecycleError("derived_input_other_consumer_unresolved")
            self._validate(db, matched[0], actor_id)
            science._evidence(db, matched[0].consumer_acceptance_id, require_retirable_models=False)
        extra = {"derived_input_registration_sha256": sha256_value(request.model_dump(mode="json")),
                 "receipt_ids": sorted(copies), "model_policy_sha256": sha256_value(policy.model_dump(mode="json")),
                 "parent_receipt_ids": sorted(selected),
                 "expires_at": expires.isoformat()}
        if frozen and any(frozen[k] != extra[k] for k in extra):
            raise LifecycleError("derived_input_retirement_evidence_changed")
        return [request.derived_input_file], extra
