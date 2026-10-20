"""Origin-owned scientific acceptance and temporary solved-model retirement.

The origin attests scientific meaning; RCN binds that attestation to the exact
producer and durable byte custody. Original manifests are never rewritten.
Model retirement shares the existing FULL-commit deletion/reader machinery,
but cannot authorize the unrelated retirement of a durable science copy.
"""
from __future__ import annotations

import json
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .hashing import sha256_value
from .models import FileRecord
from .origin_transfer import identifier, managed_path, portable_parts
from .storage_lifecycle import (
    CustodyLocation, LifecycleError, inventory_payload, inventory_sha256, _now,
)


GRACE_HOURS = 72
_DIGEST = r"^[0-9a-f]{64}$"
_SCHEMA = """
CREATE TABLE IF NOT EXISTS scientific_export_acceptances (
 acceptance_id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE NOT NULL,
 job_id TEXT NOT NULL, unit_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
 fingerprint TEXT NOT NULL, payload TEXT NOT NULL, recorded_at TEXT NOT NULL,
 revoked_at TEXT, revoke_reason TEXT);
CREATE INDEX IF NOT EXISTS scientific_export_unit
 ON scientific_export_acceptances(job_id,unit_id,attempt_id);
CREATE TABLE IF NOT EXISTS scientific_export_custody (
 receipt_id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE NOT NULL,
 acceptance_id TEXT NOT NULL, fingerprint TEXT NOT NULL, payload TEXT NOT NULL,
 recorded_at TEXT NOT NULL, revoked_at TEXT, revoke_reason TEXT);
CREATE TABLE IF NOT EXISTS scientific_model_policies (
 project_id TEXT PRIMARY KEY, payload TEXT NOT NULL, actor_id TEXT NOT NULL,
 updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scientific_retention_checks (
 acceptance_id TEXT PRIMARY KEY, checked_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scientific_model_dependencies (
 record_id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE NOT NULL,
 acceptance_id TEXT NOT NULL, dependency_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
 payload TEXT NOT NULL, recorded_at TEXT NOT NULL, revoked_at TEXT, revoke_reason TEXT);
"""


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("evidence time must include a timezone")
    if value > datetime.now(timezone.utc):
        raise ValueError("evidence time cannot be in the future")
    return value


class AnalysisReadback(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis_id: str = Field(min_length=1, max_length=192)
    input_inventory_sha256: str = Field(pattern=_DIGEST)
    output_files: list[FileRecord] = Field(min_length=1)
    completed_at: datetime
    actual_readback: Literal[True]
    completed_successfully: Literal[True]

    _time = field_validator("completed_at")(_aware)

    @field_validator("output_files")
    @classmethod
    def actual_inventory(cls, files):
        inventory_payload(files)
        return files


class ModelDependency(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dependency_id: str = Field(min_length=1, max_length=192)
    completed_at: datetime
    evidence_sha256: str = Field(pattern=_DIGEST)
    consumed_successfully: Literal[True]
    consumer_ref: str | None = Field(default=None, min_length=1, max_length=2048)
    consumer_job_id: str | None = None
    consumer_work_unit_id: str | None = None
    consumer_attempt_id: str | None = None
    consumer_request_hash: str | None = Field(default=None, pattern=_DIGEST)
    source_model_sha256s: list[str] = Field(default_factory=list)

    _time = field_validator("completed_at")(_aware)

    @model_validator(mode="after")
    def consumer_binding(self):
        ids = (self.consumer_job_id, self.consumer_work_unit_id, self.consumer_attempt_id, self.consumer_request_hash)
        if any(ids) and (not all(ids) or not self.source_model_sha256s):
            raise ValueError("a computational consumer requires its complete producer and source-model binding")
        return self


class ScientificExportAcceptance(BaseModel):
    """An authenticated origin's complete-output and critical-analysis proof.

    Coverage refers to all returned modes/items, including invalid masks, not
    just scientifically selected modes. No field-overlap assumption is made.
    """
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    idempotency_key: str
    project_id: str
    job_id: str
    request_hash: str = Field(pattern=_DIGEST)
    work_unit_id: str
    producer_attempt_id: str
    producer_external_id: str = Field(min_length=1)
    manifest_sha256: str = Field(pattern=_DIGEST)
    contract_sha256: str = Field(pattern=_DIGEST)
    scientific_files: list[FileRecord] = Field(min_length=1, max_length=100000)
    scientific_inventory_sha256: str = Field(pattern=_DIGEST)
    temporary_model_files: list[FileRecord] = Field(min_length=1, max_length=100000)
    temporary_model_storage: Literal["center_manifest", "worker_recovery"] = "center_manifest"
    temporary_inventory_file: FileRecord | None = None
    required_quantities: list[str] = Field(min_length=1)
    observed_quantities: list[str] = Field(min_length=1)
    returned_item_count: int = Field(ge=1, strict=True)
    exported_item_count: int = Field(ge=1, strict=True)
    all_returned_modes_covered: Literal[True]
    units_phase_normalization_regions_verified: Literal[True]
    validity_masks_verified: Literal[True]
    independent_readback_verified: Literal[True]
    export_accepted_at: datetime
    required_analysis_ids: list[str] = Field(min_length=1)
    critical_analyses: list[AnalysisReadback] = Field(min_length=1)
    required_dependency_ids: list[str] = Field(default_factory=list)
    completed_dependencies: list[ModelDependency] = Field(default_factory=list)
    verified_by: str
    adapter_id: str
    adapter_version: str = Field(min_length=1)
    adapter_build_sha256: str = Field(pattern=_DIGEST)
    supersedes_acceptance_ids: list[str] = Field(default_factory=list)

    _time = field_validator("export_accepted_at")(_aware)

    @field_validator("idempotency_key", "project_id", "job_id", "work_unit_id",
                     "producer_attempt_id", "verified_by", "adapter_id")
    @classmethod
    def identifiers(cls, value):
        return identifier(value)

    @model_validator(mode="after")
    def complete_contract(self):
        if inventory_sha256(self.scientific_files) != self.scientific_inventory_sha256:
            raise ValueError("scientific inventory digest mismatch")
        inventory_payload(self.temporary_model_files)
        if self.temporary_model_storage == "worker_recovery":
            if self.temporary_inventory_file is None:
                raise ValueError("worker recovery requires its original hashed result inventory")
            if any(not f.relative_path.startswith("recovery/") for f in self.temporary_model_files):
                raise ValueError("worker recovery models must stay in the managed recovery directory")
            if inventory_payload([self.temporary_inventory_file])[0] not in inventory_payload(self.scientific_files):
                raise ValueError("the temporary inventory descriptor must remain a durable science file")
        elif self.temporary_inventory_file is not None:
            raise ValueError("legacy center models are bound directly by the original manifest")
        if any(Path(f.relative_path).suffix.casefold() == ".mph" for f in self.scientific_files):
            raise ValueError("durable scientific exports cannot include solved MPH")
        if any(Path(f.relative_path).suffix.casefold() != ".mph" for f in self.temporary_model_files):
            raise ValueError("temporary model inventory must contain exact MPH files")
        if {f.relative_path.casefold() for f in self.scientific_files} & {
            f.relative_path.casefold() for f in self.temporary_model_files
        }:
            raise ValueError("science and temporary inventories overlap")
        if self.exported_item_count != self.returned_item_count:
            raise ValueError("export does not cover every returned item")
        if not set(self.required_quantities).issubset(self.observed_quantities):
            raise ValueError("required physical quantities missing")
        if len(set(self.required_quantities)) != len(self.required_quantities):
            raise ValueError("required quantities must be unique")
        for analysis in self.critical_analyses:
            if analysis.input_inventory_sha256 != self.scientific_inventory_sha256:
                raise ValueError("critical analysis did not read this scientific inventory")
        names = [a.analysis_id for a in self.critical_analyses]
        if (len(set(names)) != len(names) or len(set(self.required_analysis_ids)) != len(self.required_analysis_ids)
            or set(names) != set(self.required_analysis_ids)):
            raise ValueError("every declared critical analysis must complete exactly once")
        completed = [d.dependency_id for d in self.completed_dependencies]
        if len(set(completed)) != len(completed) or len(set(self.required_dependency_ids)) != len(self.required_dependency_ids):
            raise ValueError("dependency identifiers must be unique")
        if not set(completed).issubset(self.required_dependency_ids):
            raise ValueError("completed dependencies must be explicitly declared")
        return self


class ScientificDependencyCompletion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: str = Field(min_length=1, max_length=192)
    acceptance_id: str
    completion: ModelDependency
    verified_by: str
    adapter_id: str
    adapter_version: str
    adapter_build_sha256: str = Field(pattern=_DIGEST)

    @model_validator(mode="after")
    def explicit_consumer(self):
        if self.completion.consumer_job_id is None and not self.completion.consumer_ref:
            raise ValueError("an origin-side dependency must identify its actual consumer evidence")
        return self


class ScientificCustodyReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    idempotency_key: str
    acceptance_id: str
    scientific_inventory_sha256: str = Field(pattern=_DIGEST)
    files: list[FileRecord] = Field(min_length=1, max_length=100000)
    target: CustodyLocation
    target_kind: Literal["origin_dataset", "independent_archive"]
    verified_by: str
    adapter_id: str
    adapter_version: str = Field(min_length=1)
    adapter_build_sha256: str = Field(pattern=_DIGEST)
    verified_at: datetime
    verification_method: Literal["sha256_full_read"]
    actual_bytes_verified: Literal[True]
    durable_publication: Literal[True]
    restore_ref: str = Field(min_length=1, max_length=2048)

    _time = field_validator("verified_at")(_aware)

    @field_validator("idempotency_key", "acceptance_id", "verified_by", "adapter_id")
    @classmethod
    def identifiers(cls, value):
        return identifier(value)

    @model_validator(mode="after")
    def inventory(self):
        if inventory_sha256(self.files) != self.scientific_inventory_sha256:
            raise ValueError("custody scientific inventory digest mismatch")
        return self


class ModelRetentionException(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str
    work_unit_id: str
    producer_attempt_id: str
    relative_path: str
    reason: str = Field(min_length=1, max_length=2000)
    user_choice_ref: str = Field(min_length=1, max_length=2048)

    @field_validator("relative_path")
    @classmethod
    def exact_path(cls, value):
        portable_parts(value)
        return value


class HistoricalModelCleanupAuthorization(BaseModel):
    """A human-authorized legacy cohort; it never matches a new Attempt."""
    model_config = ConfigDict(extra="forbid")
    job_id: str
    work_unit_id: str
    producer_attempt_id: str
    reason: str = Field(min_length=1, max_length=2000)
    user_choice_ref: str = Field(min_length=1, max_length=2048)


class ModelRetirementPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_id: str
    automatic_retirement: bool = False
    grace_hours: Literal[72] = 72
    required_scientific_copies: Literal[2] = 2
    protected_relative_paths: list[str] = Field(default_factory=list)
    long_term_exceptions: list[ModelRetentionException] = Field(default_factory=list)
    historical_cleanup_authorizations: list[HistoricalModelCleanupAuthorization] = Field(default_factory=list)
    user_choice_ref: str = Field(min_length=1, max_length=2048)
    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("project_id")
    @classmethod
    def project(cls, value):
        return identifier(value)

    @field_validator("protected_relative_paths")
    @classmethod
    def protected(cls, values):
        for value in values:
            portable_parts(value)
        return values


class ScientificRetention:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle
        with lifecycle._connect() as db:
            db.executescript(_SCHEMA)

    @staticmethod
    def retirement_policy_matches(payload, expires, files):
        """Compare the effective frozen scope after current policy validation.

        The project-wide policy hash remains immutable audit evidence. An
        unrelated producer authorization or retention exception must not
        invalidate this producer's already committed operation. _evidence
        still checks the live policy, scientific custody and dependencies;
        the exact expiry and eligible inventory detect changes to this scope.
        """
        return (datetime.fromisoformat(payload["expires_at"]) == expires
                and inventory_payload(files) == payload.get("eligible_files", payload["files"]))

    def _authorize(self, proof, actor_id, *, recorded=False):
        life = self.lifecycle
        job, manifest, attempt = life._binding(proof.job_id, proof.work_unit_id, proof.producer_attempt_id)
        grant = life.repository.get_project_grant(job.project_id)
        actors = {job.user_id}
        if grant is not None:
            actors.update({grant.owner_user_id, *grant.authorized_user_ids})
        if proof.verified_by != actor_id or actor_id not in actors:
            raise LifecycleError("authenticated_adapter_actor_mismatch")
        adapter = life.repository.get_origin_adapter(proof.adapter_id)
        with life._connect() as db:
            expected_adapter = db.execute("SELECT json_extract(payload,'$.origin_adapter_id') FROM jobs WHERE job_id=?",
                                          (job.job_id,)).fetchone()[0] or "workbench"
        if (adapter is None or not adapter.active or proof.adapter_id != expected_adapter
            or (not recorded and proof.adapter_version != adapter.version) or job.execution_profile_id not in adapter.allowed_profile_ids):
            raise LifecycleError("origin_adapter_binding_mismatch")
        if (proof.project_id != job.project_id or proof.request_hash != job.request_hash
            or proof.producer_external_id != attempt.external_run_id
            or proof.manifest_sha256 != sha256_value(manifest.model_dump(mode="json"))):
            raise LifecycleError("scientific_producer_binding_mismatch")
        original = {f.relative_path.casefold(): f for f in manifest.files}
        if proof.temporary_model_storage == "worker_recovery":
            descriptor = proof.temporary_inventory_file
            expected = original.get(descriptor.relative_path.casefold())
            if expected is None or inventory_payload([expected]) != inventory_payload([descriptor]):
                raise LifecycleError("temporary_inventory_not_in_original_manifest")
            if descriptor.size_bytes > 64 * 1024 * 1024:
                raise LifecycleError("temporary_inventory_descriptor_too_large")
            path = managed_path(life._directory(job, proof.work_unit_id, proof.producer_attempt_id), descriptor.relative_path)
            life._verify_source(path, descriptor.model_dump(mode="json"))
            with path.open("rb") as stream:
                raw = stream.read(64 * 1024 * 1024 + 1)
            if len(raw) != descriptor.size_bytes or hashlib.sha256(raw).hexdigest() != descriptor.sha256:
                raise LifecycleError("temporary_inventory_binding_mismatch")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise LifecycleError("temporary_inventory_invalid")
            records = data.get("temporary_model_inventory")
            if not isinstance(records, list) or not records or len(records) > 100000:
                raise LifecycleError("temporary_inventory_invalid")
            declared = []
            contract_hashes = set()
            for entry in records:
                if (not isinstance(entry, dict) or entry.get("storage_kind") != "worker_recovery"
                    or not isinstance(entry.get("output_contract_sha256"), str)
                    or len(entry["output_contract_sha256"]) != 64
                    or any(c not in "0123456789abcdef" for c in entry["output_contract_sha256"])
                    or not all(k in entry for k in ("relative_path", "size_bytes", "sha256"))):
                    raise LifecycleError("temporary_inventory_invalid")
                declared.append(FileRecord.model_validate({k: entry[k] for k in ("relative_path", "size_bytes", "sha256")}))
                contract_hashes.add(entry["output_contract_sha256"])
            if len(contract_hashes) != 1:
                raise LifecycleError("temporary_inventory_contract_mismatch")
            if inventory_payload(declared) != inventory_payload(proof.temporary_model_files):
                raise LifecycleError("temporary_inventory_binding_mismatch")
        for file in proof.temporary_model_files:
            expected = original.get(file.relative_path.casefold())
            if proof.temporary_model_storage == "center_manifest" and (expected is None or inventory_payload([file]) != inventory_payload([expected])):
                raise LifecycleError("temporary_model_not_in_original_manifest")
            # Input baselines are never result retirement candidates, even if a
            # project worker accidentally copies one into its output inventory.
            protected_hashes = {f.sha256 for f in job.input_manifest
                                if f.relative_path.casefold().endswith(".mph")}
            if job.template_sha256:
                protected_hashes.add(job.template_sha256)
            if file.sha256 in protected_hashes:
                raise LifecycleError("source_baseline_protected")
        for file in proof.scientific_files:
            expected = original.get(file.relative_path.casefold())
            if expected is not None and inventory_payload([file]) != inventory_payload([expected]):
                raise LifecycleError("original_scientific_file_changed")
        for dependency in proof.completed_dependencies:
            self._verify_dependency(proof, dependency)
        return job, manifest, attempt

    def _verify_dependency(self, proof, dependency):
        if dependency.dependency_id not in proof.required_dependency_ids:
            raise LifecycleError("model_dependency_not_declared")
        if dependency.consumer_job_id is None:
            return  # Origin-side analyses/transforms are attested by the owning adapter.
        job, manifest, attempt = self.lifecycle._binding(dependency.consumer_job_id,
            dependency.consumer_work_unit_id, dependency.consumer_attempt_id)
        if (dependency.consumer_request_hash != job.request_hash
            or dependency.evidence_sha256 != sha256_value(manifest.model_dump(mode="json"))):
            raise LifecycleError("model_consumer_binding_mismatch")
        parent_hashes = {f.sha256 for f in proof.temporary_model_files}
        consumed_hashes = {f.sha256 for f in job.input_manifest}
        if job.template_sha256:
            consumed_hashes.add(job.template_sha256)
        if not set(dependency.source_model_sha256s).issubset(parent_hashes & consumed_hashes):
            raise LifecycleError("model_consumer_did_not_bind_source")
        consumer_times = [t for t in (attempt.finished_at, attempt.collected_at) if t is not None]
        if consumer_times and dependency.completed_at < max(consumer_times):
            raise LifecycleError("model_consumer_completion_predates_actual_evidence")

    def record_dependency(self, receipt: ScientificDependencyCompletion, *, actor_id):
        receipt = ScientificDependencyCompletion.model_validate(receipt)
        proof = self.get_acceptance(receipt.acceptance_id)
        authorized = proof.model_copy(update={key: getattr(receipt, key) for key in
            ("verified_by", "adapter_id", "adapter_version", "adapter_build_sha256")})
        self._authorize(authorized, actor_id)
        self._verify_dependency(proof, receipt.completion)
        payload = receipt.model_dump(mode="json")
        fingerprint = sha256_value(payload)
        key = "science-dependency-" + sha256_value(receipt.idempotency_key)[:32]
        life = self.lifecycle
        with life._transaction() as db:
            prior = db.execute("SELECT * FROM scientific_model_dependencies WHERE idempotency_key=?", (receipt.idempotency_key,)).fetchone()
            if prior is not None:
                if prior["fingerprint"] != fingerprint:
                    raise LifecycleError("idempotency_key_conflict")
                return {"record_id": key, "payload": json.loads(prior["payload"]), "already_present": True,
                        "revoked": prior["revoked_at"] is not None}
            db.execute("INSERT INTO scientific_model_dependencies "
                "(record_id,idempotency_key,acceptance_id,dependency_id,fingerprint,payload,recorded_at) VALUES(?,?,?,?,?,?,?)",
                (key, receipt.idempotency_key, receipt.acceptance_id, receipt.completion.dependency_id, fingerprint, life._json(payload), _now()))
            life._audit(db, "storage.model_dependency_completed", actor_id, key,
                        acceptance_id=receipt.acceptance_id, dependency_id=receipt.completion.dependency_id)
        return {"record_id": key, "payload": payload, "already_present": False, "revoked": False}

    def record_acceptance(self, proof: ScientificExportAcceptance, *, actor_id):
        proof = ScientificExportAcceptance.model_validate(proof)
        self._authorize(proof, actor_id)
        payload = proof.model_dump(mode="json")
        key = "science-" + sha256_value(proof.idempotency_key)[:32]
        return self._record("scientific_export_acceptances", key, proof.idempotency_key, payload,
                            actor_id, unit=(proof.job_id, proof.work_unit_id, proof.producer_attempt_id),
                            supersedes=proof.supersedes_acceptance_ids)

    def _record(self, table, record_id, idempotency_key, payload, actor_id, *, unit=None, acceptance_id=None, supersedes=()):
        life = self.lifecycle
        fingerprint = sha256_value(payload)
        with life._transaction() as db:
            previous = db.execute(f"SELECT * FROM {table} WHERE idempotency_key=?", (idempotency_key,)).fetchone()
            if previous is not None:
                if previous["fingerprint"] != fingerprint:
                    raise LifecycleError("idempotency_key_conflict")
                return {"record_id": record_id, "payload": json.loads(previous["payload"]),
                        "already_present": True, "revoked": previous["revoked_at"] is not None}
            if unit is not None:
                active_rows = db.execute("SELECT acceptance_id,payload FROM scientific_export_acceptances "
                    "WHERE job_id=? AND unit_id=? AND attempt_id=? AND revoked_at IS NULL", unit).fetchall()
                active = {row[0] for row in active_rows}
                # Historical backfills may cover disjoint parts of one original
                # Unit. Keep their science, custody and deletion identities live;
                # replacing an overlapping inventory still needs explicit consent.
                selected = {f["relative_path"].casefold() for f in payload["temporary_model_files"]}
                disjoint_append = not supersedes and all(
                    selected.isdisjoint(f["relative_path"].casefold()
                        for f in json.loads(row[1])["temporary_model_files"])
                    for row in active_rows)
                if not disjoint_append and (active != set(supersedes) or len(supersedes) != len(set(supersedes))):
                    raise LifecycleError("active_scientific_acceptance_requires_explicit_supersession")
                for prior_id in supersedes:
                    db.execute("UPDATE scientific_export_acceptances SET revoked_at=?,revoke_reason=? WHERE acceptance_id=?",
                               (_now(), "explicitly_superseded_by:" + record_id, prior_id))
                    life._audit(db, "storage.scientific_acceptance_superseded", actor_id, prior_id, replacement_id=record_id)
                db.execute("INSERT INTO scientific_export_acceptances "
                    "(acceptance_id,idempotency_key,job_id,unit_id,attempt_id,fingerprint,payload,recorded_at) "
                    "VALUES(?,?,?,?,?,?,?,?)", (record_id, idempotency_key, *unit, fingerprint, life._json(payload), _now()))
            else:
                db.execute("INSERT INTO scientific_export_custody "
                    "(receipt_id,idempotency_key,acceptance_id,fingerprint,payload,recorded_at) VALUES(?,?,?,?,?,?)",
                    (record_id, idempotency_key, acceptance_id, fingerprint, life._json(payload), _now()))
            life._audit(db, "storage.scientific_evidence_recorded", actor_id, record_id,
                        evidence_table=table, fingerprint=fingerprint)
        return {"record_id": record_id, "payload": payload, "already_present": False, "revoked": False}

    def get_acceptance(self, acceptance_id):
        with self.lifecycle._connect() as db:
            row = db.execute("SELECT * FROM scientific_export_acceptances WHERE acceptance_id=?", (acceptance_id,)).fetchone()
        if row is None:
            raise LifecycleError("scientific_acceptance_not_found")
        if row["revoked_at"] is not None:
            raise LifecycleError("scientific_acceptance_revoked")
        return ScientificExportAcceptance.model_validate_json(row["payload"])

    def record_custody(self, receipt: ScientificCustodyReceipt, *, actor_id):
        receipt = ScientificCustodyReceipt.model_validate(receipt)
        proof = self.get_acceptance(receipt.acceptance_id)
        authorized = proof.model_copy(update={"verified_by": receipt.verified_by, "adapter_id": receipt.adapter_id,
            "adapter_version": receipt.adapter_version, "adapter_build_sha256": receipt.adapter_build_sha256})
        self._authorize(authorized, actor_id)
        if (receipt.scientific_inventory_sha256 != proof.scientific_inventory_sha256
            or inventory_payload(receipt.files) != inventory_payload(proof.scientific_files)):
            raise LifecycleError("scientific_custody_inventory_mismatch")
        key = "science-custody-" + sha256_value(receipt.idempotency_key)[:32]
        return self._record("scientific_export_custody", key, receipt.idempotency_key,
                            receipt.model_dump(mode="json"), actor_id, acceptance_id=receipt.acceptance_id)

    def revoke(self, record_id, *, actor_id, reason):
        if not reason.strip():
            raise LifecycleError("reason_required")
        table, column = (("scientific_export_custody", "receipt_id") if record_id.startswith("science-custody-")
                         else (("scientific_model_dependencies", "record_id") if record_id.startswith("science-dependency-")
                               else ("scientific_export_acceptances", "acceptance_id")))
        with self.lifecycle._transaction() as db:
            result = db.execute(f"UPDATE {table} SET revoked_at=COALESCE(revoked_at,?),revoke_reason=? WHERE {column}=?",
                                (_now(), reason, record_id))
            if result.rowcount != 1:
                raise LifecycleError("scientific_evidence_not_found")
            self.lifecycle._audit(db, "storage.scientific_evidence_revoked", actor_id, record_id, reason=reason)

    def register_policy(self, policy: ModelRetirementPolicy, *, actor_id):
        policy = ModelRetirementPolicy.model_validate(policy)
        if self.lifecycle.repository.get_project_grant(policy.project_id) is None:
            raise LifecycleError("project_unregistered")
        with self.lifecycle._transaction() as db:
            db.execute("INSERT INTO scientific_model_policies VALUES(?,?,?,?) ON CONFLICT(project_id) DO UPDATE "
                       "SET payload=excluded.payload,actor_id=excluded.actor_id,updated_at=excluded.updated_at",
                       (policy.project_id, self.lifecycle._json(policy.model_dump(mode="json")), actor_id, _now()))
            self.lifecycle._audit(db, "storage.model_policy_registered", actor_id, policy.project_id,
                                 policy=policy.model_dump(mode="json"))
        return policy

    def get_policy(self, project_id):
        """Read the exact existing policy before any operator update."""
        if self.lifecycle.repository.get_project_grant(project_id) is None:
            raise LifecycleError("project_unregistered")
        with self.lifecycle._connect() as db:
            row = db.execute("SELECT * FROM scientific_model_policies WHERE project_id=?", (project_id,)).fetchone()
        return {"project_id": project_id, "policy": json.loads(row["payload"]) if row else None,
                "actor_id": row["actor_id"] if row else None, "updated_at": row["updated_at"] if row else None}

    def _evidence(self, db, acceptance_id, *, receipt_ids=None, now=None, require_retirable_models=True):
        life = self.lifecycle
        row = db.execute("SELECT * FROM scientific_export_acceptances WHERE acceptance_id=?", (acceptance_id,)).fetchone()
        if row is None or row["revoked_at"] is not None:
            raise LifecycleError("scientific_acceptance_missing_or_revoked")
        proof = ScientificExportAcceptance.model_validate_json(row["payload"])
        job, manifest, attempt = self._authorize(proof, proof.verified_by, recorded=True)
        row = db.execute("SELECT payload FROM scientific_model_policies WHERE project_id=?", (proof.project_id,)).fetchone()
        if row is None:
            raise LifecycleError("model_policy_unregistered")
        policy = ModelRetirementPolicy.model_validate_json(row[0])
        if not policy.automatic_retirement:
            raise LifecycleError("automatic_model_retirement_disabled")
        dependencies = {d.dependency_id: d for d in proof.completed_dependencies}
        for dependency_row in db.execute("SELECT payload FROM scientific_model_dependencies WHERE acceptance_id=? AND revoked_at IS NULL ORDER BY recorded_at",
                                         (acceptance_id,)).fetchall():
            receipt = ScientificDependencyCompletion.model_validate_json(dependency_row[0])
            self._verify_dependency(proof, receipt.completion)
            dependency = receipt.completion
            current = dependencies.get(dependency.dependency_id)
            if current is None or dependency.completed_at > current.completed_at:
                dependencies[dependency.dependency_id] = dependency
        if set(dependencies) != set(proof.required_dependency_ids):
            raise LifecycleError("model_dependencies_incomplete")
        copies = {}
        for row in db.execute("SELECT * FROM scientific_export_custody WHERE acceptance_id=? AND revoked_at IS NULL",
                              (acceptance_id,)):
            if receipt_ids is not None and row["receipt_id"] not in receipt_ids:
                continue
            custody = ScientificCustodyReceipt.model_validate_json(row["payload"])
            if (custody.scientific_inventory_sha256 == proof.scientific_inventory_sha256
                and inventory_payload(custody.files) == inventory_payload(proof.scientific_files)):
                copies[row["receipt_id"]] = custody
        if receipt_ids is not None and set(copies) != set(receipt_ids):
            raise LifecycleError("scientific_custody_revoked_or_changed")
        if len({c.target.physical_key() for c in copies.values()}) < 2:
            raise LifecycleError("scientific_independent_copies_missing")
        if receipt_ids is None:
            # A redundant third copy made later must not restart an already
            # satisfied handoff window. Choose the earliest independently
            # verified pair, and freeze these exact receipts in the intent.
            selected, devices = {}, set()
            for key, custody in sorted(copies.items(), key=lambda item: (item[1].verified_at, item[0])):
                physical = custody.target.physical_key()
                if physical in devices:
                    continue
                selected[key] = custody
                devices.add(physical)
                if len(devices) == 2:
                    break
            copies = selected
        # A relay may be the second durable SCIENCE device. It cannot count as a
        # surviving device when retiring that same SCIENCE relay.
        gate_times = [proof.export_accepted_at, *(a.completed_at for a in proof.critical_analyses),
                      *(d.completed_at for d in dependencies.values()),
                      *(c.verified_at for c in copies.values())]
        historical = any((entry.job_id, entry.work_unit_id, entry.producer_attempt_id) ==
                         (proof.job_id, proof.work_unit_id, proof.producer_attempt_id)
                         for entry in policy.historical_cleanup_authorizations)
        expires = max(gate_times) + timedelta(hours=0 if historical else policy.grace_hours)
        if (now or datetime.now(timezone.utc)) < expires:
            raise LifecycleError("model_grace_period_active")
        files = [f for f in proof.temporary_model_files if not self._protected(f.relative_path, proof, policy)]
        if require_retirable_models and not files:
            raise LifecycleError("all_temporary_models_protected")
        return proof, job, manifest, attempt, policy, copies, expires, files

    @staticmethod
    def _protected(path, proof, policy):
        if path.casefold() in {p.casefold() for p in policy.protected_relative_paths}:
            return True
        return any((e.job_id, e.work_unit_id, e.producer_attempt_id, e.relative_path.casefold()) ==
                   (proof.job_id, proof.work_unit_id, proof.producer_attempt_id, path.casefold())
                   for e in policy.long_term_exceptions)

    def preview(self, acceptance_id, *, now=None):
        try:
            with self.lifecycle._connect() as db:
                proof, job, manifest, attempt, policy, copies, expires, files = self._evidence(db, acceptance_id, now=now)
                if db.execute("SELECT 1 FROM storage_lifecycle_readers WHERE job_id=? AND unit_id=? AND attempt_id=?",
                              (proof.job_id, proof.work_unit_id, proof.producer_attempt_id)).fetchone():
                    raise LifecycleError("live_readers")
            return {"eligible": True, "reason_code": "scientific_acceptance_and_handoff_satisfied",
                "operation_kind": "solved_model", "acceptance_id": acceptance_id,
                "job_id": proof.job_id, "work_unit_id": proof.work_unit_id,
                "producer_attempt_id": proof.producer_attempt_id, "manifest_sha256": proof.manifest_sha256,
                "files": inventory_payload(files), "receipt_ids": sorted(copies),
                "model_policy_sha256": sha256_value(policy.model_dump(mode="json")),
                "expires_at": expires.isoformat(), "size_bytes": sum(f.size_bytes for f in files),
                "restore_refs": [c.restore_ref for c in copies.values()]}
        except (OSError, ValueError) as exc:
            return {"eligible": False, "acceptance_id": acceptance_id,
                    "reason_code": getattr(exc, "reason_code", "scientific_evidence_invalid")}

    def create_retirement(self, acceptance_id, *, idempotency_key, actor_id):
        identifier(idempotency_key)
        life = self.lifecycle
        if self.get_acceptance(acceptance_id).temporary_model_storage != "center_manifest":
            raise LifecycleError("worker_adapter_execution_required")
        operation = {"operation_kind": "solved_model", "acceptance_id": acceptance_id}
        fingerprint = sha256_value(operation)
        with life._connect() as db:
            old = db.execute("SELECT * FROM storage_lifecycle_intents WHERE idempotency_key=?", (idempotency_key,)).fetchone()
        if old is not None:
            if old["fingerprint"] != fingerprint:
                raise LifecycleError("idempotency_key_conflict")
            return life.get_intent(old["intent_id"])
        candidate = self.preview(acceptance_id)
        if not candidate["eligible"]:
            raise LifecycleError(candidate["reason_code"])
        proof = self.get_acceptance(acceptance_id)
        job, manifest, _ = life._binding(proof.job_id, proof.work_unit_id, proof.producer_attempt_id)
        if life.center_binding is None:
            raise LifecycleError("center_identity_unregistered")
        directory = life._directory(job, proof.work_unit_id, proof.producer_attempt_id)
        identities = {}
        for file in candidate["files"]:
            path = managed_path(directory, file["relative_path"])
            before = life._file_identity(path)
            life._verify_source(path, file)
            if before != life._file_identity(path):
                raise LifecycleError("source_file_changed")
            identities[file["relative_path"]] = before
        payload = {**candidate, "original_manifest": manifest.model_dump(mode="json"),
                   "center_binding": life.center_binding.model_dump(mode="json"), "file_identities": identities}
        intent_id = "model-retire-" + sha256_value(idempotency_key)[:32]
        with life._transaction() as db:
            self.check_intent(db, payload)
            old = db.execute("SELECT * FROM storage_lifecycle_intents WHERE idempotency_key=?", (idempotency_key,)).fetchone()
            if old is not None:
                if old["fingerprint"] != fingerprint:
                    raise LifecycleError("idempotency_key_conflict")
                intent_id = old["intent_id"]
            else:
                prior = db.execute("SELECT payload FROM storage_lifecycle_intents WHERE job_id=? AND unit_id=? AND attempt_id=? "
                    "AND (operation_kind='solved_model' OR operation_kind LIKE 'solved_model:%')", (proof.job_id, proof.work_unit_id, proof.producer_attempt_id)).fetchall()
                selected = {f['relative_path'].casefold() for f in candidate['files']}
                if any(not selected.isdisjoint(f['relative_path'].casefold()
                       for f in json.loads(row[0])['files']) for row in prior):
                    raise LifecycleError("model_retirement_already_has_original_key")
                db.execute("INSERT INTO storage_lifecycle_intents "
                    "(intent_id,idempotency_key,job_id,unit_id,attempt_id,fingerprint,payload,state,created_at,operation_kind) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)", (intent_id, idempotency_key, proof.job_id, proof.work_unit_id,
                            proof.producer_attempt_id, fingerprint, life._json(payload), "pending", _now(),
                            "solved_model:" + acceptance_id if prior else "solved_model"))
                for file in candidate["files"]:
                    db.execute("INSERT INTO storage_lifecycle_deletions VALUES(?,?,?,?)",
                               (intent_id, file["relative_path"], "pending", _now()))
                life._audit(db, "storage.model_retirement_committed", actor_id, intent_id, **operation,
                            files=candidate["files"], expires_at=candidate["expires_at"])
        return life.get_intent(intent_id)

    def check_intent(self, db, payload):
        proof, job, manifest, attempt, policy, copies, expires, files = self._evidence(
            db, payload["acceptance_id"], receipt_ids=payload["receipt_ids"])
        life = self.lifecycle
        if (proof.manifest_sha256 != payload["manifest_sha256"] or life.center_binding is None
            or life.center_binding.model_dump(mode="json") != payload["center_binding"]):
            raise LifecycleError("retirement_binding_changed")
        if not self.retirement_policy_matches(payload, expires, files):
            raise LifecycleError("model_retirement_policy_changed")
        if db.execute("SELECT 1 FROM storage_lifecycle_readers WHERE job_id=? AND unit_id=? AND attempt_id=?",
                      (proof.job_id, proof.work_unit_id, proof.producer_attempt_id)).fetchone():
            raise LifecycleError("live_readers")
        for permit in db.execute("SELECT p.* FROM storage_lifecycle_writer_permits p JOIN storage_lifecycle_intents i "
                "ON i.intent_id=p.intent_id WHERE i.job_id=? AND i.unit_id=? AND i.attempt_id=? AND i.operation_kind='relay_copy'",
                (proof.job_id, proof.work_unit_id, proof.producer_attempt_id)).fetchall():
            if not life._reconcile_dead_writer(db, permit):
                raise LifecycleError("file_retirement_in_progress")
        return job

    def reader_gate(self, db, payload, relative_path):
        if relative_path not in {f["relative_path"] for f in payload["files"]}:
            return
        try:
            proof, _, _, _, policy, _, expires, files = self._evidence(db, payload["acceptance_id"], receipt_ids=payload["receipt_ids"])
        except LifecycleError:
            # Revoked custody/policy must allow diagnostics on a remaining file.
            return
        if (relative_path not in {f.relative_path for f in files}
            or not self.retirement_policy_matches(payload, expires, files)):
            return
        raise LifecycleError("result_retirement_pending_or_completed")

    def state(self, job_id, unit_id, attempt_id):
        life = self.lifecycle
        with life._connect() as db:
            acceptances = [dict(r) for r in db.execute("SELECT acceptance_id,payload,revoked_at FROM "
                "scientific_export_acceptances WHERE job_id=? AND unit_id=? AND attempt_id=?",
                (job_id, unit_id, attempt_id))]
            intents = [r[0] for r in db.execute("SELECT intent_id FROM storage_lifecycle_intents WHERE job_id=? "
                "AND unit_id=? AND attempt_id=? AND (operation_kind='solved_model' OR operation_kind LIKE 'solved_model:%' OR "
                "operation_kind LIKE 'solved_model_origin:%' OR operation_kind LIKE 'solved_model_worker:%')", (job_id, unit_id, attempt_id))]
            for entry in acceptances:
                entry["acceptance"] = json.loads(entry.pop("payload"))
            dependencies = [{"record_id": row["record_id"], "payload": json.loads(row["payload"]), "revoked": row["revoked_at"] is not None}
                for row in db.execute("SELECT d.* FROM scientific_model_dependencies d JOIN scientific_export_acceptances a "
                    "ON a.acceptance_id=d.acceptance_id WHERE a.job_id=? AND a.unit_id=? AND a.attempt_id=?", (job_id, unit_id, attempt_id))]
            scientific_custody = [{"receipt_id": row["receipt_id"],
                "acceptance_id": row["acceptance_id"], "receipt": json.loads(row["payload"]),
                "revoked": row["revoked_at"] is not None, "revoked_at": row["revoked_at"],
                "recorded_at": row["recorded_at"]}
                for row in db.execute("SELECT c.* FROM scientific_export_custody c "
                    "JOIN scientific_export_acceptances a ON a.acceptance_id=c.acceptance_id "
                    "WHERE a.job_id=? AND a.unit_id=? AND a.attempt_id=? "
                    "ORDER BY c.recorded_at,c.receipt_id", (job_id, unit_id, attempt_id))]
        return {"acceptances": acceptances, "dependencies": dependencies,
                "scientific_custody": scientific_custody,
                "model_retirements": [life.get_intent(i) for i in intents]}

    def run_gc_batch(self, *, max_units=4, max_files=16, stop_event=None):
        life = self.lifecycle
        with life._connect() as db:
            rows = db.execute("SELECT a.acceptance_id,a.job_id,a.unit_id,a.attempt_id FROM scientific_export_acceptances a "
                "LEFT JOIN scientific_retention_checks c ON c.acceptance_id=a.acceptance_id "
                "WHERE a.revoked_at IS NULL AND COALESCE(json_extract(a.payload,'$.temporary_model_storage'),'center_manifest')='center_manifest' "
                "AND NOT EXISTS (SELECT 1 FROM storage_lifecycle_intents i WHERE (i.operation_kind='solved_model' OR i.operation_kind LIKE 'solved_model:%') "
                "AND json_extract(i.payload,'$.acceptance_id')=a.acceptance_id AND i.state='completed') "
                "ORDER BY COALESCE(c.checked_at,''),a.recorded_at LIMIT ?", (max_units,)).fetchall()
        results, remaining = [], max_files
        for row in rows:
            if remaining <= 0 or (stop_event is not None and stop_event.is_set()):
                break
            with life._transaction() as db:
                db.execute("INSERT INTO scientific_retention_checks VALUES(?,?) ON CONFLICT(acceptance_id) "
                           "DO UPDATE SET checked_at=excluded.checked_at", (row[0], _now()))
                previous = db.execute("SELECT intent_id FROM storage_lifecycle_intents WHERE job_id=? AND unit_id=? "
                    "AND attempt_id=? AND (operation_kind='solved_model' OR operation_kind LIKE 'solved_model:%') AND json_extract(payload,'$.acceptance_id')=?",
                    (*tuple(row[1:]), row[0])).fetchone()
            try:
                intent = life.get_intent(previous[0]) if previous else self.create_retirement(row[0],
                    idempotency_key="auto-model-" + sha256_value(row[0])[:32], actor_id="storage-gc")
                if intent["state"] == "completed":
                    continue
                count = min(remaining, sum(v == "pending" for v in intent["files"].values()))
                results.append(life.run_retirement(intent["intent_id"], max_files=max(1, count), stop_event=stop_event))
                remaining -= count
            except (OSError, ValueError) as exc:
                results.append({"acceptance_id": row[0], "eligible": False,
                    "reason_code": getattr(exc, "reason_code", "scientific_evidence_invalid")})
        return results
