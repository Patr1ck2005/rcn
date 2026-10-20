from datetime import datetime, timedelta, timezone

from research_compute_network.capacity import (
    PressureTracker,
    effective_capacity,
    effective_comsol_capacity,
    has_external_pressure,
)
from research_compute_network.models import (
    ExternalPressureSnapshot,
    MachineExecutionConfig,
    ExternalPressureSnapshot,
    MachineExecutionConfig,
    MachineOperationalStatus,
    PressurePolicySettings,
    PressureState,
    SupervisorState,
    TelemetryState,
    TransportState,
    ExternalLoadSnapshot,
)

from conftest import open_machine


def _sample(**changes):
    # 45% sits above the aligned 40% CPU/GPU threshold defaults so the
    # hysteresis test exercises timing, not the threshold value itself. The
    # previous 12% only worked while the CPU default was the asymmetric 10%
    # that derated owner-active desktops.
    return ExternalPressureSnapshot(
        external_comsol_count=1,
        external_comsol_cpu_percent=45,
        **changes,
    )


def test_pressure_requires_enter_hysteresis_and_clears_after_quiet_window():
    start = datetime(2026, 8, 18, tzinfo=timezone.utc)
    tracker = PressureTracker()
    assert tracker.update(_sample(observed_at=start), now=start).state == PressureState.CANDIDATE
    assert tracker.update(_sample(observed_at=start + timedelta(seconds=29)), now=start + timedelta(seconds=29)).state == PressureState.CANDIDATE
    assert tracker.update(_sample(observed_at=start + timedelta(seconds=30)), now=start + timedelta(seconds=30)).state == PressureState.PRESSURED
    quiet = tracker.update(ExternalPressureSnapshot(observed_at=start + timedelta(seconds=31)), now=start + timedelta(seconds=31))
    assert quiet.state == PressureState.PRESSURED
    assert tracker.update(ExternalPressureSnapshot(observed_at=start + timedelta(seconds=151)), now=start + timedelta(seconds=151)).state == PressureState.NORMAL


def test_idle_resident_comsol_uses_resource_gate_instead_of_pressure_by_default():
    idle = ExternalPressureSnapshot(
        external_comsol_count=1,
        external_comsol_cpu_percent=0.02,
        external_comsol_memory_mb=5 * 1024,
        external_gpu_utilization_percent=0,
    )
    assert not has_external_pressure(idle, available_memory_mb=20 * 1024)
    tracked = PressureTracker().update(idle, available_memory_mb=20 * 1024)
    assert tracked.state == PressureState.NORMAL
    assert "below thresholds" in tracked.reason
    assert "resource gate" in tracked.reason


def test_generic_external_load_uses_cpu_and_gpu_but_process_count_is_diagnostic_only():
    busy_cpu = ExternalLoadSnapshot(
        external_process_count=7,
        external_cpu_percent=91,
        attribution_quality="complete",
    )
    assert has_external_pressure(busy_cpu)
    busy_gpu = ExternalLoadSnapshot(
        external_process_count=1,
        external_gpu_utilization_percent=88,
        attribution_quality="complete",
    )
    assert has_external_pressure(busy_gpu)
    resident_only = ExternalLoadSnapshot(
        external_process_count=99,
        attribution_quality="complete",
    )
    assert not has_external_pressure(resident_only)


def test_generic_external_load_memory_and_disk_reserves_are_global_gates():
    snapshot = ExternalLoadSnapshot(attribution_quality="complete")
    assert has_external_pressure(snapshot, available_memory_mb=4096, memory_reserve_mb=8192)
    assert has_external_pressure(snapshot, free_disk_mb=1024, disk_reserve_mb=2048)
    assert not has_external_pressure(snapshot, available_memory_mb=16384, memory_reserve_mb=8192)


def test_degraded_attribution_warns_without_cpu_or_gpu_pressure():
    snapshot = ExternalLoadSnapshot(
        external_process_count=4,
        external_cpu_percent=99,
        attribution_quality="degraded",
    )
    assert not has_external_pressure(snapshot)
    tracked = PressureTracker().update(snapshot)
    assert tracked.state == PressureState.NORMAL
    assert "telemetry_attribution_degraded" in tracked.reason_codes


def test_memory_pressure_modes_are_administrator_configurable():
    idle = ExternalPressureSnapshot(
        external_comsol_count=1,
        external_comsol_memory_mb=5 * 1024,
    )
    low_headroom = PressurePolicySettings(
        memory_mode="low_headroom",
        available_memory_floor_mb=8 * 1024,
    )
    assert has_external_pressure(idle, policy=low_headroom, available_memory_mb=6 * 1024)
    assert not has_external_pressure(idle, policy=low_headroom, available_memory_mb=20 * 1024)
    assert has_external_pressure(idle, policy=PressurePolicySettings(memory_mode="absolute"))


def test_effective_capacity_applies_to_all_profiles_and_stale_telemetry():
    now = datetime(2026, 8, 18, tzinfo=timezone.utc)
    normal = effective_comsol_capacity(
        policy_cap=3,
        execution_cap=3,
        profile_cap=3,
        profile_id="workbench-comsol-scan-v1",
        pressure=ExternalPressureSnapshot(),
        telemetry_state=TelemetryState.LIVE,
        now=now,
    )
    assert normal.effective_cap == 3
    pressured = effective_comsol_capacity(
        policy_cap=3,
        execution_cap=3,
        profile_cap=3,
        profile_id="workbench-comsol-scan-v1",
        pressure=ExternalPressureSnapshot(state=PressureState.PRESSURED),
        telemetry_state=TelemetryState.LIVE,
        now=now,
    )
    assert pressured.effective_cap == 1
    configured_pressure = effective_comsol_capacity(
        policy_cap=3,
        execution_cap=3,
        profile_cap=3,
        profile_id="workbench-comsol-scan-v1",
        pressure=ExternalPressureSnapshot(state=PressureState.PRESSURED),
        telemetry_state=TelemetryState.LIVE,
        settings=PressurePolicySettings(pressured_dispatch_cap=2),
        now=now,
    )
    assert configured_pressure.effective_cap == 2
    candidate = effective_comsol_capacity(
        policy_cap=3,
        execution_cap=3,
        profile_cap=3,
        profile_id="workbench-comsol-scan-v1",
        pressure=ExternalPressureSnapshot(state=PressureState.CANDIDATE),
        telemetry_state=TelemetryState.LIVE,
        now=now,
    )
    assert candidate.effective_cap == 3
    assert candidate.state == PressureState.CANDIDATE
    stale = effective_comsol_capacity(
        policy_cap=3,
        execution_cap=3,
        profile_cap=3,
        profile_id="workbench-comsol-scan-v1",
        pressure=ExternalPressureSnapshot(),
        telemetry_state=TelemetryState.STALE,
        now=now,
    )
    assert stale.effective_cap == 1
    other = effective_comsol_capacity(
        policy_cap=3,
        execution_cap=3,
        profile_cap=3,
        profile_id="project-worker-v1",
        pressure=ExternalPressureSnapshot(state=PressureState.PRESSURED),
        telemetry_state=TelemetryState.LIVE,
        now=now,
    )
    assert other.effective_cap == 1


def test_same_generic_pressure_cap_applies_to_non_comsol_profiles():
    now = datetime(2026, 8, 18, tzinfo=timezone.utc)
    for profile_id in ("workbench-comsol-scan-v1", "project-worker-v1", "example-batch-v1"):
        decision = effective_capacity(
            policy_cap=3,
            execution_cap=3,
            target_cap=3,
            profile_cap=None,
            profile_id=profile_id,
            pressure=ExternalLoadSnapshot(state=PressureState.PRESSURED),
            telemetry_state=TelemetryState.LIVE,
            now=now,
        )
        assert decision.effective_cap == 1


def test_active_override_restores_static_cap_but_never_bypasses_stale_telemetry():
    now = datetime(2026, 8, 18, tzinfo=timezone.utc)
    decision = effective_comsol_capacity(
        policy_cap=3,
        execution_cap=3,
        profile_cap=3,
        profile_id="workbench-comsol-scan-v1",
        pressure=ExternalPressureSnapshot(state=PressureState.PRESSURED),
        telemetry_state=TelemetryState.LIVE,
        override_until=now + timedelta(minutes=30),
        now=now,
    )
    assert decision.state == PressureState.OVERRIDE
    assert decision.effective_cap == 3
    stale = effective_comsol_capacity(
        policy_cap=3,
        execution_cap=3,
        profile_cap=3,
        profile_id="workbench-comsol-scan-v1",
        pressure=ExternalPressureSnapshot(state=PressureState.PRESSURED),
        telemetry_state=TelemetryState.STALE,
        override_until=now + timedelta(minutes=30),
        now=now,
    )
    assert stale.state == PressureState.TELEMETRY_STALE
    assert stale.effective_cap == 1


def test_admin_override_uses_requested_cap_but_not_profile_or_static_hard_caps():
    now = datetime(2026, 8, 18, tzinfo=timezone.utc)
    decision = effective_comsol_capacity(
        policy_cap=4,
        execution_cap=3,
        target_cap=1,
        profile_cap=2,
        profile_id="workbench-comsol-scan-v1",
        pressure=ExternalPressureSnapshot(state=PressureState.PRESSURED),
        telemetry_state=TelemetryState.LIVE,
        override_until=now + timedelta(minutes=10),
        override_cap=3,
        now=now,
    )
    assert decision.normal_cap == 1
    assert decision.effective_cap == 2
    assert decision.state == PressureState.OVERRIDE


def test_partial_runtime_updates_preserve_capacity_but_observed_normal_can_clear(service):
    now = datetime(2026, 8, 18, tzinfo=timezone.utc)
    machine, policy = open_machine()
    service.register_machine(machine, policy, actor_id="admin")
    service.repository.put_machine_execution_config(MachineExecutionConfig(
        machine_id=machine.machine_id,
        root_uuid="root-capacity",
        max_concurrent_units=2,
    ))
    service.update_operational_status(MachineOperationalStatus(
        machine_id=machine.machine_id,
        transport_state=TransportState.CONNECTED,
        supervisor_state=SupervisorState.ONLINE,
        telemetry_state=TelemetryState.LIVE,
        pressure_state=PressureState.PRESSURED,
        effective_comsol_concurrency=1,
        capacity_reason="external COMSOL pressure above threshold",
        capacity_decision_at=now,
    ), actor_id="monitor")
    partial = service.update_operational_status(MachineOperationalStatus(
        machine_id=machine.machine_id,
        transport_state=TransportState.CONNECTED,
        supervisor_state=SupervisorState.ONLINE,
        telemetry_state=TelemetryState.LIVE,
    ), actor_id="monitor")
    assert partial.pressure_state == PressureState.PRESSURED
    observed_clear = service.update_operational_status(MachineOperationalStatus(
        machine_id=machine.machine_id,
        transport_state=TransportState.CONNECTED,
        supervisor_state=SupervisorState.ONLINE,
        telemetry_state=TelemetryState.LIVE,
        pressure_state=PressureState.NORMAL,
        effective_comsol_concurrency=2,
        capacity_reason="external COMSOL pressure cleared",
        capacity_decision_at=now + timedelta(seconds=120),
    ), actor_id="monitor")
    assert observed_clear.pressure_state == PressureState.NORMAL
    assert observed_clear.effective_comsol_concurrency == 2
    stale = service.update_operational_status(MachineOperationalStatus(
        machine_id=machine.machine_id,
        transport_state=TransportState.CONNECTED,
        supervisor_state=SupervisorState.ONLINE,
        telemetry_state=TelemetryState.STALE,
    ), actor_id="monitor")
    assert stale.pressure_state == PressureState.TELEMETRY_STALE
    assert stale.effective_comsol_concurrency == 1


def test_candidate_pressure_flapping_does_not_flood_audit_events(service):
    now = datetime(2026, 8, 18, tzinfo=timezone.utc)
    machine, policy = open_machine()
    service.register_machine(machine, policy, actor_id="admin")
    service.repository.put_machine_execution_config(MachineExecutionConfig(
        machine_id=machine.machine_id,
        root_uuid="root-pressure-events",
        max_concurrent_units=2,
    ))

    def update(state, capacity, offset):
        return service.update_operational_status(MachineOperationalStatus(
            machine_id=machine.machine_id,
            transport_state=TransportState.CONNECTED,
            supervisor_state=SupervisorState.ONLINE,
            telemetry_state=TelemetryState.LIVE,
            pressure_state=state,
            effective_comsol_concurrency=capacity,
            capacity_reason=state.value,
            capacity_decision_at=now + timedelta(seconds=offset),
            last_checked_at=now + timedelta(seconds=offset),
        ), actor_id="monitor")

    update(PressureState.NORMAL, 2, 0)
    initial = len([
        event for event in service.repository.list_events()
        if event.event_type == "machine.pressure_changed"
        and event.subject_id == machine.machine_id
    ])
    update(PressureState.CANDIDATE, 2, 1)
    update(PressureState.NORMAL, 2, 2)
    after_flap = len([
        event for event in service.repository.list_events()
        if event.event_type == "machine.pressure_changed"
        and event.subject_id == machine.machine_id
    ])
    assert after_flap == initial

    update(PressureState.PRESSURED, 1, 32)
    enforced = [
        event for event in service.repository.list_events()
        if event.event_type == "machine.pressure_changed"
        and event.subject_id == machine.machine_id
    ]
    assert len(enforced) == initial + 1
    assert enforced[0].details["pressure_state"] == "pressured"
