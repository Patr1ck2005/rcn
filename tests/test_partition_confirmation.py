"""Missing estimates must solicit a user decision, never silently fragment."""

import json
from io import BytesIO
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient

from research_compute_network.api import create_app
from research_compute_network.client import RcnApiError, RcnClient
from research_compute_network.models import AtomicComputeItem, PartitionRequest, ResourceRequest
from research_compute_network.partitioning import PartitionConfirmationRequired, create_partition_plan
from conftest import approved_grant


def request(count=3, **overrides):
    return PartitionRequest(
        origin_submitter_id="origin-test", user_id="user-a", project_id="demo-analysis",
        execution_profile_id="workbench-comsol-scan-v1", request_hash="a" * 64,
        items=[AtomicComputeItem(item_id=f"point-{i}", ordinal=i, payload={"k_idx": i}) for i in range(count)],
        resources=ResourceRequest(cpus=1, memory_mb=512, disk_mb=1), **overrides,
    )


@pytest.mark.parametrize("count", [2, 1891, 2001])
def test_unknown_durations_cannot_silently_generate_one_unit_per_atom(count):
    with pytest.raises(PartitionConfirmationRequired) as caught:
        create_partition_plan(request(count))
    assert caught.value.detail()["missing_item_count"] == count
    assert "请主动询问用户" in str(caught.value)
    assert "不要自行猜测" in str(caught.value)


def test_partial_estimates_are_not_filled_with_target_duration():
    req = request()
    req.items[0].estimated_duration_s = 30
    with pytest.raises(PartitionConfirmationRequired) as caught:
        create_partition_plan(req)
    assert caught.value.missing_item_count == 2
    req.estimated_seconds_per_item = 60
    plan = create_partition_plan(req)
    assert len(plan.work_units) == 1
    assert plan.work_units[0].expected_duration_s == 150


def test_complete_estimates_pack_large_input_deterministically_and_respect_quota():
    req = request(1891, estimated_seconds_per_item=30)
    plan = create_partition_plan(req)
    assert len(plan.work_units) == 32
    assert plan.plan_hash == create_partition_plan(req.model_copy(deep=True)).plan_hash
    assert [i for unit in plan.work_units for i in unit.atomic_item_ids] == [i.item_id for i in req.items]
    assert len(create_partition_plan(req, max_queued_units=10).work_units) <= 10
    req.estimated_seconds_per_item = None
    for item in req.items:
        item.estimated_duration_s = 30
    assert len(create_partition_plan(req).work_units) == 32


def test_single_atom_and_explicit_user_count_remain_supported():
    assert len(create_partition_plan(request(1)).work_units) == 1
    assert [len(u.atomic_item_ids) for u in create_partition_plan(request(10, requested_unit_count=3)).work_units] == [4, 3, 3]


@pytest.mark.parametrize("explicit", [False, True])
def test_setup_isolation_and_order_survive_confirmation_guard(explicit):
    req = request(6, requested_unit_count=2 if explicit else None,
                  estimated_seconds_per_item=None if explicit else 30)
    req.partition_constraints.prohibit_mixed_setup_fingerprints = True
    for i, item in enumerate(req.items):
        item.setup_fingerprint = ("a" if i < 3 else "b") * 64
    plan = create_partition_plan(req)
    assert [u.atomic_item_ids for u in plan.work_units] == [["point-0", "point-1", "point-2"], ["point-3", "point-4", "point-5"]]
    req.requested_unit_count = 1
    with pytest.raises(ValueError, match="setup fingerprints isolated"):
        create_partition_plan(req)


def test_http_error_is_structured_and_legacy_plan_read_confirm_and_resume_remain_valid(service, tmp_path):
    service.register_project(approved_grant(), actor_id="admin")
    # Emulate the stored pre-0.14.2 grouping without invoking new planning for
    # an ambiguous request. Old request data still loads without validation.
    old_plan = create_partition_plan(request(3, requested_unit_count=3))
    old_plan.request.requested_unit_count = None
    service.repository.put_partition_plan(old_plan)
    client = TestClient(create_app(database_url=f"sqlite:///{(tmp_path / 'pilot.db').as_posix()}", allow_local_trusted=True))
    denied = client.post("/v1/partition-plans", json=request().model_dump(mode="json"))
    assert denied.status_code == 400
    detail = denied.json()["detail"]
    assert detail["reason_code"] == "partition_duration_confirmation_required"
    assert detail["requires"] == "user_confirmation"
    assert detail["next_action"] == "ask_user_for_duration_estimates_or_unit_count"
    assert "请主动询问用户" in detail["message"]
    loaded = client.get(f"/v1/partition-plans/{old_plan.plan_id}")
    assert loaded.status_code == 200
    assert loaded.json()["request"]["requested_unit_count"] is None
    first = client.post(f"/v1/partition-plans/{old_plan.plan_id}/confirm")
    second = client.post(f"/v1/partition-plans/{old_plan.plan_id}/confirm")
    assert first.status_code == second.status_code == 200
    assert first.json()["job_id"] == second.json()["job_id"]
    assert [u["work_unit_id"] for u in first.json()["work_units"]] == [u.work_unit_id for u in old_plan.work_units]
    assert len(service.repository.list_partition_plans()) == 1


@pytest.mark.parametrize("study", [False, True])
def test_sdk_preserves_user_prompt_and_does_not_retry_or_bypass(monkeypatch, study):
    calls = []
    def rejected(req, **kwargs):
        calls.append(req.full_url)
        body = json.dumps({"detail": PartitionConfirmationRequired(3).detail()}).encode()
        raise HTTPError(req.full_url, 400, "Bad Request", {}, BytesIO(body))
    monkeypatch.setattr("research_compute_network.client.urlopen", rejected)
    client = RcnClient()
    with pytest.raises(RcnApiError) as caught:
        if study:
            client.plan_declarative_study(request(), origin_adapter_id="adapter-test")
        else:
            client.plan_partition(request())
    assert caught.value.status == 400
    assert caught.value.reason_code == "partition_duration_confirmation_required"
    assert "请主动询问用户" in str(caught.value) and "不要自行猜测" in str(caught.value)
    assert calls == ["http://127.0.0.1:8765/v1/partition-plans"]
