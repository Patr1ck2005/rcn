from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from test_storage_lifecycle import custody, selection, ready
from research_compute_network.hashing import sha256_value
from research_compute_network.models import FileRecord
from research_compute_network.scientific_retention import (
    AnalysisReadback, HistoricalModelCleanupAuthorization, ModelDependency, ModelRetirementPolicy, ModelRetentionException,
    ScientificCustodyReceipt, ScientificExportAcceptance,
)
from research_compute_network.storage_lifecycle import (
    CustodyLocation, LifecycleError, StorageLifecycle, inventory_sha256,
)


def evidence(h, *, key="original-scientific-proof", age=100, dependencies=False):
    science = [f for f in h.manifest.files if not f.relative_path.endswith(".mph")]
    digest = inventory_sha256(science)
    when = datetime.now(timezone.utc) - timedelta(hours=age)
    analyses = [AnalysisReadback(analysis_id="critical-readback", input_inventory_sha256=digest,
        output_files=[FileRecord(relative_path="analysis/critical.json", size_bytes=2,
            sha256=hashlib.sha256(b"{}").hexdigest())], completed_at=when,
        actual_readback=True, completed_successfully=True)]
    return ScientificExportAcceptance(idempotency_key=key, project_id=h.job.project_id,
        job_id=h.job.job_id, request_hash=h.job.request_hash, work_unit_id=h.unit.work_unit_id,
        producer_attempt_id="attempt-original", producer_external_id="run-original",
        manifest_sha256=sha256_value(h.manifest.model_dump(mode="json")), contract_sha256="a" * 64,
        scientific_files=science, scientific_inventory_sha256=digest,
        temporary_model_files=[f for f in h.manifest.files if f.relative_path.endswith(".mph")],
        required_quantities=["frequency", "radiation_complex", "power", "regional_integrals"],
        observed_quantities=["frequency", "radiation_complex", "power", "regional_integrals"],
        returned_item_count=2, exported_item_count=2, all_returned_modes_covered=True,
        units_phase_normalization_regions_verified=True, validity_masks_verified=True,
        independent_readback_verified=True, export_accepted_at=when,
        required_analysis_ids=["critical-readback"], critical_analyses=analyses,
        required_dependency_ids=["harmonic-source"] if dependencies else [],
        completed_dependencies=[ModelDependency(dependency_id="harmonic-source", completed_at=when,
            evidence_sha256="b" * 64, consumed_successfully=True)] if dependencies else [],
        verified_by="alice", adapter_id="workbench", adapter_version="test-v1", adapter_build_sha256="b" * 64)


def accepted(h, *, age=100, copies=2, physicals=None, dependencies=False):
    life = h.lifecycle.scientific
    proof = evidence(h, age=age, dependencies=dependencies)
    life.register_policy(ModelRetirementPolicy(project_id="fixture", automatic_retirement=True,
        reason="Explicit fixture model policy", user_choice_ref="fixture:human-choice"), actor_id="admin")
    recorded = life.record_acceptance(proof, actor_id="alice")
    acceptance_id = recorded["record_id"]
    records = []
    for i in range(copies):
        copy = ScientificCustodyReceipt(idempotency_key=f"scientific-copy-{i}", acceptance_id=acceptance_id,
            scientific_inventory_sha256=proof.scientific_inventory_sha256, files=proof.scientific_files,
            target=CustodyLocation(host_id=f"host-{i}", store_id=f"store-{i}", volume_id=f"volume-{i}",
                generation="1", physical_device_id=physicals[i] if physicals else f"device-{i}"),
            target_kind="origin_dataset" if i == 0 else "independent_archive", verified_by="alice",
            adapter_id="workbench", adapter_version="test-v1", adapter_build_sha256="b" * 64,
            verified_at=proof.export_accepted_at, verification_method="sha256_full_read",
            actual_bytes_verified=True, durable_publication=True, restore_ref=f"fixture:science-{i}")
        records.append(life.record_custody(copy, actor_id="alice"))
    return acceptance_id, proof, records


def test_complete_proof_rejects_missing_modes_quantities_analysis_and_dependencies(custody):
    payload = evidence(custody, dependencies=True).model_dump(mode="json")
    for patch in [{"exported_item_count": 1}, {"observed_quantities": ["frequency"]},
                  {"required_dependency_ids": []}, {"critical_analyses": []},
                  {"required_analysis_ids": ["missing-analysis"]},
                  {"independent_readback_verified": False}]:
        with pytest.raises(ValidationError):
            ScientificExportAcceptance.model_validate({**payload, **patch})


def test_exact_72_hours_from_last_gate_not_model_age(custody):
    acceptance_id, proof, receipts = accepted(custody, age=80)
    first = custody.lifecycle.scientific.preview(acceptance_id, now=proof.export_accepted_at + timedelta(hours=72))
    assert first["eligible"]
    assert not custody.lifecycle.scientific.preview(acceptance_id,
        now=proof.export_accepted_at + timedelta(hours=72) - timedelta(microseconds=1))["eligible"]
    recent = proof.model_dump(mode="json")
    recent["idempotency_key"] = "recent-analysis"
    recent["supersedes_acceptance_ids"] = [acceptance_id]
    recent["critical_analyses"][0]["completed_at"] = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
    late = ScientificExportAcceptance.model_validate(recent)
    result = custody.lifecycle.scientific.record_acceptance(late, actor_id="alice")
    for n, entry in enumerate(receipts):
        payload = {**entry["payload"], "idempotency_key": f"late-copy-{n}", "acceptance_id": result["record_id"]}
        custody.lifecycle.scientific.record_custody(ScientificCustodyReceipt.model_validate(payload), actor_id="alice")
    assert custody.lifecycle.scientific.preview(result["record_id"])["reason_code"] == "model_grace_period_active"
    assert custody.lifecycle.scientific.preview(acceptance_id)["reason_code"] == "scientific_acceptance_missing_or_revoked"


def test_last_custody_gate_defers_expiry(custody):
    acceptance_id, proof, receipts = accepted(custody, copies=1)
    payload = {**receipts[0]["payload"], "idempotency_key": "late-second-copy",
        "target": {**receipts[0]["payload"]["target"], "physical_device_id": "different-device"},
        "verified_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()}
    custody.lifecycle.scientific.record_custody(ScientificCustodyReceipt.model_validate(payload), actor_id="alice")
    assert custody.lifecycle.scientific.preview(acceptance_id)["reason_code"] == "model_grace_period_active"


def test_same_disk_is_one_science_copy_and_wkr_may_be_second(custody):
    acceptance_id, proof, receipts = accepted(custody, physicals=["same", "same"])
    assert custody.lifecycle.scientific.preview(acceptance_id)["reason_code"] == "scientific_independent_copies_missing"
    payload = {**receipts[0]["payload"], "idempotency_key": "center-second-copy", "target": custody.binding.model_dump(mode="json")}
    custody.lifecycle.scientific.record_custody(ScientificCustodyReceipt.model_validate(payload), actor_id="alice")
    assert custody.lifecycle.scientific.preview(acceptance_id)["eligible"]
    assert custody.lifecycle.preview_retirement(*selection(custody))["reason_code"] == "project_policy_unregistered"


def test_model_only_retirement_preserves_original_manifest_and_science(custody):
    h = custody
    acceptance_id, proof, _ = accepted(h)
    original = h.manifest.model_dump(mode="json")
    started = h.lifecycle.scientific.create_retirement(acceptance_id, idempotency_key="model-original", actor_id="admin")
    assert started["operation_kind"] == "solved_model"
    assert h.lifecycle.scientific.create_retirement(acceptance_id, idempotency_key="model-original", actor_id="admin") == started
    finished = h.lifecycle.run_retirement(started["intent_id"])
    assert finished["state"] == "completed"
    assert not (h.directory / "models/result.mph").exists()
    assert (h.directory / "metrics.csv").exists()
    assert (h.directory / "unlisted-evidence.json").exists()
    assert h.repo.list_artifact_manifests(h.job.job_id)[0].model_dump(mode="json") == original
    restarted = StorageLifecycle(h.repo, h.root, center_binding=h.binding)
    assert restarted.scientific.state(*selection(h))["model_retirements"][0]["state"] == "completed"
    assert restarted.run_retirement(started["intent_id"])["state"] == "completed"
    ready(h)
    assert h.lifecycle.preview_retirement(*selection(h))["reason_code"] == "scientific_inventory_requires_separate_relay_policy"


def test_active_reader_blocks_and_science_remains_readable_after_intent(custody):
    h = custody
    acceptance_id, _, _ = accepted(h)
    with h.lifecycle.pin_reader(*selection(h), "models/result.mph"):
        assert h.lifecycle.scientific.preview(acceptance_id)["reason_code"] == "live_readers"
    pending = h.lifecycle.scientific.create_retirement(acceptance_id, idempotency_key="model-original", actor_id="admin")
    with pytest.raises(LifecycleError, match="result_retirement_pending_or_completed"):
        h.lifecycle.pin_reader(*selection(h), "models/result.mph")
    with h.lifecycle.pin_reader(*selection(h), "metrics.csv"):
        assert h.lifecycle.run_retirement(pending["intent_id"])["last_reason"] == "live_readers"
    assert h.lifecycle.run_retirement(pending["intent_id"])["state"] == "completed"


def test_revocation_blocks_pending_delete_and_permits_diagnostics(custody):
    h = custody
    acceptance_id, _, receipts = accepted(h)
    pending = h.lifecycle.scientific.create_retirement(acceptance_id, idempotency_key="model-original", actor_id="admin")
    h.lifecycle.scientific.revoke(receipts[0]["record_id"], actor_id="admin", reason="Device offline")
    assert h.lifecycle.run_retirement(pending["intent_id"])["last_reason"] == "scientific_custody_revoked_or_changed"
    assert (h.directory / "models/result.mph").exists()
    with h.lifecycle.pin_reader(*selection(h), "models/result.mph"):
        pass


def test_user_exception_and_policy_change_protect_model(custody):
    h = custody
    acceptance_id, _, _ = accepted(h)
    pending = h.lifecycle.scientific.create_retirement(acceptance_id, idempotency_key="model-original", actor_id="admin")
    exception = ModelRetentionException(job_id=h.job.job_id, work_unit_id=h.unit.work_unit_id,
        producer_attempt_id="attempt-original", relative_path="models/result.mph", reason="Explicit research use",
        user_choice_ref="fixture:user-selected-this-model")
    h.lifecycle.scientific.register_policy(ModelRetirementPolicy(project_id="fixture", automatic_retirement=True,
        reason="User selected model", user_choice_ref="fixture:user", long_term_exceptions=[exception]), actor_id="admin")
    assert h.lifecycle.run_retirement(pending["intent_id"])["last_reason"] == "all_temporary_models_protected"
    assert (h.directory / "models/result.mph").exists()


def test_unrelated_historical_policy_append_does_not_restart_center_retirement(custody):
    h = custody
    acceptance_id, _, _ = accepted(h)
    pending = h.lifecycle.scientific.create_retirement(acceptance_id,
        idempotency_key="center-scope-original", actor_id="admin")
    frozen = h.lifecycle.get_intent(pending["intent_id"])["candidate"]
    policy = ModelRetirementPolicy.model_validate(h.lifecycle.scientific.get_policy("fixture")["policy"])
    policy.historical_cleanup_authorizations.append(HistoricalModelCleanupAuthorization(
        job_id=h.job.job_id, work_unit_id="other-unit", producer_attempt_id="other-attempt",
        reason="Another completed legacy cohort", user_choice_ref="fixture:human"))
    h.lifecycle.scientific.register_policy(policy, actor_id="admin")
    with pytest.raises(LifecycleError, match="result_retirement_pending_or_completed"):
        with h.lifecycle.pin_reader(*selection(h), "models/result.mph"):
            pass
    result = h.lifecycle.run_retirement(pending["intent_id"])
    assert result["state"] == "completed"
    assert h.lifecycle.get_intent(pending["intent_id"])["candidate"] == frozen
    assert not (h.directory / "models/result.mph").exists()


def test_changed_model_and_wrong_actor_never_retire(custody):
    h = custody
    with pytest.raises(LifecycleError, match="authenticated_adapter_actor_mismatch"):
        h.lifecycle.scientific.record_acceptance(evidence(h), actor_id="bob")
    acceptance_id, _, _ = accepted(h)
    pending = h.lifecycle.scientific.create_retirement(acceptance_id, idempotency_key="model-original", actor_id="admin")
    (h.directory / "models/result.mph").write_bytes(b"new scientific evidence")
    assert h.lifecycle.run_retirement(pending["intent_id"])["last_reason"] == "source_file_changed"
    assert (h.directory / "models/result.mph").exists()


def test_bounded_background_model_gc(custody):
    h = custody
    acceptance_id, _, _ = accepted(h)
    result = h.lifecycle.run_gc_batch(max_units=1, max_files=1)
    assert any(r.get("operation_kind") == "solved_model" and r["state"] == "completed" for r in result)
    assert not (h.directory / "models/result.mph").exists()
    assert (h.directory / "metrics.csv").exists()


def test_newer_redundant_copy_does_not_restart_grace(custody):
    h = custody
    acceptance_id, _, receipts = accepted(h)
    payload = {**receipts[0]["payload"], "idempotency_key": "redundant-late-third-copy",
        "target": {**receipts[0]["payload"]["target"], "physical_device_id": "third-device"},
        "verified_at": datetime.now(timezone.utc).isoformat()}
    h.lifecycle.scientific.record_custody(ScientificCustodyReceipt.model_validate(payload), actor_id="alice")
    assert h.lifecycle.scientific.preview(acceptance_id)["eligible"]


def test_model_retirement_preserves_legacy_relay_intent_and_blocks_its_execution(custody):
    h = custody
    ready(h)
    relay = h.lifecycle.create_retirement(*selection(h), idempotency_key="legacy-relay", actor_id="admin")
    acceptance_id, _, _ = accepted(h)
    model = h.lifecycle.scientific.create_retirement(acceptance_id, idempotency_key="model-original", actor_id="admin")
    assert relay["intent_id"] != model["intent_id"]
    restarted = StorageLifecycle(h.repo, h.root, center_binding=h.binding)
    assert restarted.run_retirement(relay["intent_id"])["last_reason"] == "scientific_inventory_requires_separate_relay_policy"
    assert restarted.run_retirement(model["intent_id"])["state"] == "completed"
    assert (h.directory / "metrics.csv").exists()


def test_crash_after_unlink_replays_original_model_intent(custody, monkeypatch):
    h = custody
    acceptance_id, _, _ = accepted(h)
    pending = h.lifecycle.scientific.create_retirement(acceptance_id, idempotency_key="model-original", actor_id="admin")
    original = h.lifecycle._audit

    def crash(db, event, actor, subject, **details):
        if event == "storage.file_retired":
            raise RuntimeError("fixture process crash after unlink")
        return original(db, event, actor, subject, **details)

    monkeypatch.setattr(h.lifecycle, "_audit", crash)
    with pytest.raises(RuntimeError, match="fixture process crash"):
        h.lifecycle.run_retirement(pending["intent_id"])
    assert not (h.directory / "models/result.mph").exists()
    restarted = StorageLifecycle(h.repo, h.root, center_binding=h.binding)
    result = restarted.run_retirement(pending["intent_id"])
    assert result["state"] == "completed"
    assert result["files"]["models/result.mph"] == "already_absent"


def test_scientific_routes_require_owner_and_admin(custody):
    import secrets
    from fastapi import FastAPI, HTTPException
    from fastapi.testclient import TestClient
    from research_compute_network.auth import PilotAuthenticator
    from research_compute_network.models import ApiTokenRecord, UserAccount, UserRole
    from research_compute_network.storage_lifecycle_api import build_storage_lifecycle_router

    h = custody
    tokens = {}
    for user, roles in [("alice", {UserRole.MEMBER}), ("bob", {UserRole.MEMBER}), ("admin", {UserRole.ADMIN})]:
        raw = secrets.token_hex(20)
        tokens[user] = {"Authorization": "Bearer " + raw}
        h.repo.put_user(UserAccount(user_id=user, display_name=user, roles=roles))
        h.repo.put_token(ApiTokenRecord(user_id=user, token_hash=hashlib.sha256(raw.encode()).hexdigest(), scopes={"api"}))
    app = FastAPI()

    def owner(job, context):
        if context.actor_id != job.user_id:
            raise HTTPException(403, "origin owner required")

    app.include_router(build_storage_lifecycle_router(lifecycle=h.lifecycle,
        auth=PilotAuthenticator(h.repo, allow_local_trusted=False), require_owner=owner))
    client = TestClient(app)
    url = f"/v1/jobs/{h.job.job_id}/units/{h.unit.work_unit_id}/scientific-exports"
    payload = evidence(h).model_dump(mode="json")
    assert client.post(url, json=payload).status_code == 401
    assert client.post(url, json=payload, headers=tokens["bob"]).status_code == 403
    result = client.post(url, json=payload, headers=tokens["alice"])
    assert result.status_code == 200, result.text
    assert client.post(url, json=payload, headers=tokens["alice"]).json()["already_present"]
    policy = ModelRetirementPolicy(project_id="fixture", automatic_retirement=True,
        user_choice_ref="fixture:user", reason="fixture policy").model_dump(mode="json")
    policy_url = "/v1/admin/storage/projects/fixture/model-policy"
    assert client.put(policy_url, json=policy, headers=tokens["alice"]).status_code == 403
    assert client.put(policy_url, json=policy, headers=tokens["admin"]).status_code == 200
    bad = {**payload, "returned_item_count": 3}
    assert client.post(url, json=bad, headers=tokens["alice"]).status_code == 422
